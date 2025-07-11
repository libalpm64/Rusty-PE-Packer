use rusty_pe_packer::{
    anti_analysis::{verify_cpu, verify_ram, verify_processes},
    anti_debug::{is_debugger_present, process_list},
    exception_handler::trigger_execution,
};

fn main() {
    verify_ram();
    verify_cpu();
    verify_processes();
    
    is_debugger_present();
    process_list();

    println!("Starting..");
    trigger_execution();
    println!("Execution complete");
}
