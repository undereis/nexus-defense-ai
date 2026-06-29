// Impede uma janela de console extra no Windows em release (inofensivo no macOS).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    nexus_client_lib::run()
}
