// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::virtualization::analyze::analyze;
use linuxdoctor::modules::virtualization::collect::{
    parse_container_ps, parse_container_stats, parse_dominfo, parse_vm_names, ContainerInfo,
    ToolInventory, VirtualizationRawData, VmInfo,
};

fn test_context() -> Context {
    Context {
        hostname: "test-host".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

fn empty_vm_inventory() -> ToolInventory<VmInfo> {
    ToolInventory {
        runtime: None,
        available: false,
        unavailable_reason: Some("virsh is not installed".to_string()),
        items: vec![],
    }
}

fn empty_container_inventory() -> ToolInventory<ContainerInfo> {
    ToolInventory {
        runtime: None,
        available: false,
        unavailable_reason: Some("neither docker nor podman is installed".to_string()),
        items: vec![],
    }
}

#[test]
fn bare_metal_no_hosted_workloads_fixture_is_all_info() {
    let data = VirtualizationRawData {
        tool_available: true,
        vm_type: Some("none".to_string()),
        container_type: Some("none".to_string()),
        cpuinfo_hypervisor_flag: false,
        vm_inventory: empty_vm_inventory(),
        container_inventory: empty_container_inventory(),
    };
    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert!(findings[0].explanation.contains("bare metal"));
    // No VMs/containers hosted -> only the 3 summary findings.
    assert_eq!(findings.len(), 3);
}

/// A hypervisor host: bare metal itself (VIRT001), but hosting one VM via
/// libvirt and one container via Docker. Uses the exact `virsh dominfo`
/// format and the real captured `docker ps`/`stats` output shapes.
#[test]
fn hypervisor_host_with_real_vm_and_container_shapes() {
    let dominfo_text = "\
Name:           web1
State:          running
CPU(s):         4
CPU time:       12345.6s
Max memory:     4194304 KiB
Used memory:    2097152 KiB
Autostart:      enable
";
    let vm = parse_dominfo("web1", dominfo_text);
    assert_eq!(parse_vm_names("web1\n"), vec!["web1".to_string()]);

    let ps_text = "web-frontend\trunning\tUp 3 hours\tnginx:latest\n";
    let stats_text = "web-frontend\t1.23%\t45.6MiB / 2GiB\t2.28%\n";
    let mut containers = parse_container_ps(ps_text);
    let stats = parse_container_stats(stats_text);
    for c in &mut containers {
        if let Some((cpu, mem, mem_pct)) = stats.get(&c.name) {
            c.cpu_percent = Some(cpu.clone());
            c.mem_usage = Some(mem.clone());
            c.mem_percent = Some(mem_pct.clone());
        }
    }

    let data = VirtualizationRawData {
        tool_available: true,
        vm_type: Some("none".to_string()),
        container_type: Some("none".to_string()),
        cpuinfo_hypervisor_flag: false,
        vm_inventory: ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![vm],
        },
        container_inventory: ToolInventory {
            runtime: Some("docker".to_string()),
            available: true,
            unavailable_reason: None,
            items: containers,
        },
    };

    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));

    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"VIRT002"));
    assert!(ids.contains(&"VIRT003"));
    assert!(ids.contains(&"VIRT004"));
    assert!(ids.contains(&"VIRT005"));

    let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
    assert_eq!(virt003.instance.as_deref(), Some("web1"));
    assert!(virt003.explanation.contains("4 vCPU"));

    let virt005 = findings.iter().find(|f| f.id == "VIRT005").unwrap();
    assert_eq!(virt005.instance.as_deref(), Some("web-frontend"));
    assert!(virt005.explanation.contains("1.23% CPU"));
}

#[test]
fn container_without_stats_still_reports_state_and_image() {
    let containers: Vec<ContainerInfo> =
        parse_container_ps("db1\texited\tExited (0) 2 days ago\tpostgres:15\n");
    let data = VirtualizationRawData {
        tool_available: true,
        vm_type: Some("none".to_string()),
        container_type: Some("none".to_string()),
        cpuinfo_hypervisor_flag: false,
        vm_inventory: empty_vm_inventory(),
        container_inventory: ToolInventory {
            runtime: Some("docker".to_string()),
            available: true,
            unavailable_reason: None,
            items: containers,
        },
    };
    let findings = analyze(&data, &test_context());
    let virt005 = findings.iter().find(|f| f.id == "VIRT005").unwrap();
    assert!(virt005.explanation.contains("Exited (0)"));
    assert!(virt005.explanation.contains("postgres:15"));
    // No stats for a stopped container -> no "Currently using" note.
    assert!(!virt005.explanation.contains("Currently using"));
}
