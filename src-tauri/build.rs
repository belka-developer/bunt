fn main() {
    // На Windows exe просит права администратора (манифест рядом).
    let attrs = tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("windows-app.manifest")),
    );
    tauri_build::try_build(attrs).expect("не удалось собрать ресурсы Windows");
}
