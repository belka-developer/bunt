// В релизной сборке не показываем консольное окно.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    bunt_lib::run()
}
