// Ponto de entrada do app Tauri. Registra o plugin HTTP, que faz as requisições
// à API REST do Nexus a partir do Rust (nativo) — por isso NÃO depende de CORS
// no servidor (o motor Python e a API ficam intactos).

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .run(tauri::generate_context!())
        .expect("erro ao iniciar a aplicação Tauri");
}
