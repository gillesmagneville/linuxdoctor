// SPDX-License-Identifier: GPL-3.0-only

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

use crate::core::command::{record_timeouts, take_timeouts};

/// Applies `f` to every item on a small pool of threads and returns the
/// results **in the order of `items`**.
///
/// For work that is one slow external command per independent item — the
/// canonical case is `smartctl` on each disk — where doing them one after
/// another makes a 12-disk server wait 12 times as long as it needs to.
///
/// - At most `max_threads` run at once, so a 60-disk machine does not
///   launch 60 `smartctl` processes simultaneously.
/// - Zero or one item runs inline on the calling thread, with no thread
///   at all.
/// - Commands stopped for exceeding their time limit inside `f` are
///   carried back to the calling thread (in item order), so the module's
///   report still lists them. Without this they would be lost with the
///   worker thread.
/// - If `f` panics, the panic propagates to the caller, exactly as it
///   would in a plain loop; the engine isolates it to the module.
pub fn parallel_map<T, R, F>(items: &[T], max_threads: usize, f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    if items.len() <= 1 || max_threads <= 1 {
        return items.iter().map(&f).collect();
    }

    let next = AtomicUsize::new(0);
    let workers = max_threads.min(items.len());
    let (tx, rx) = mpsc::channel::<(usize, R, Vec<String>)>();

    thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let (next, f) = (&next, &f);
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(index) else {
                    break;
                };
                let _ = take_timeouts();
                let result = f(item);
                let _ = tx.send((index, result, take_timeouts()));
            });
        }
        drop(tx);
    });

    let mut done: Vec<(usize, R, Vec<String>)> = rx.into_iter().collect();
    done.sort_by_key(|(index, _, _)| *index);
    done.into_iter()
        .map(|(_, result, timeouts)| {
            record_timeouts(timeouts);
            result
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::command;
    use std::time::{Duration, Instant};

    #[test]
    fn results_follow_input_order_even_when_completion_order_differs() {
        let delays = [120u64, 0, 60, 0, 30];
        let out = parallel_map(&delays, 4, |ms| {
            thread::sleep(Duration::from_millis(*ms));
            *ms
        });
        assert_eq!(out, delays);
    }

    #[test]
    fn runs_concurrently_but_never_more_than_the_cap() {
        // Eight 200 ms jobs on 4 threads: two waves, ~400 ms. Fully
        // sequential would be 1600 ms; unbounded would be ~200 ms.
        let items = [0u8; 8];
        let started = Instant::now();
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        parallel_map(&items, 4, |_| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(200));
            running.fetch_sub(1, Ordering::SeqCst);
        });
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(1100), "took {elapsed:?}");
        assert!(
            peak.load(Ordering::SeqCst) <= 4,
            "peak {}",
            peak.load(Ordering::SeqCst)
        );
        assert!(peak.load(Ordering::SeqCst) >= 2, "no concurrency observed");
    }

    #[test]
    fn empty_and_single_item_inputs_run_inline() {
        let none: [u8; 0] = [];
        assert!(parallel_map(&none, 4, |_| 1).is_empty());

        let caller = thread::current().id();
        let out = parallel_map(&[7u8], 4, |n| (thread::current().id(), *n));
        assert_eq!(out, vec![(caller, 7)]);
    }

    #[test]
    fn a_cap_of_one_is_a_plain_sequential_loop() {
        let caller = thread::current().id();
        let out = parallel_map(&[1, 2, 3], 1, |_| thread::current().id());
        assert!(out.iter().all(|id| *id == caller));
    }

    #[test]
    fn stopped_commands_inside_workers_reach_the_callers_notes_in_item_order() {
        let _ = take_timeouts();
        let items = ["first", "second", "third"];
        parallel_map(&items, 3, |label| {
            // Each job runs a command that exceeds its limit; the label
            // (the sleep duration) tells the notes apart.
            let secs = match *label {
                "first" => "31",
                "second" => "32",
                _ => "33",
            };
            let _ = command("sleep")
                .arg(secs)
                .timeout(Duration::from_millis(150))
                .output();
        });
        let notes = take_timeouts();
        assert_eq!(notes.len(), 3, "{notes:?}");
        assert!(notes[0].contains("sleep 31"), "{notes:?}");
        assert!(notes[1].contains("sleep 32"), "{notes:?}");
        assert!(notes[2].contains("sleep 33"), "{notes:?}");
    }

    #[test]
    fn a_panic_in_a_worker_reaches_the_caller() {
        let result = std::panic::catch_unwind(|| {
            parallel_map(&[1, 2, 3], 3, |n| {
                if *n == 2 {
                    panic!("worker failed");
                }
                *n
            })
        });
        assert!(result.is_err());
    }
}
