; Хуки установщика Бунта. Подключены в tauri.conf.json (bundle.windows.nsis.installerHooks).

; При удалении программы убираем всё, что Бунт мог оставить вне своей папки: задачу планировщика автозапуска
; с правами администратора и запись обычного автозапуска. Обновление через Бунт запускает установщик с /UPDATE
; и старую программу не удаляет, а при переустановке поверх установщик вызывает программу удаления с параметром _?=.
; В обоих случаях автозапуск должен остаться.
!macro NSIS_HOOK_PREUNINSTALL
  ${GetOptions} $CMDLINE "_?=" $R8
  ${If} ${Errors}
  ${AndIf} $UpdateMode <> 1
    nsExec::Exec 'schtasks /Delete /TN "Bunt-AdminAutostart" /F'
    Pop $R8
    nsExec::Exec 'schtasks /Delete /TN "Bunt" /F'
    Pop $R8
    ; запись Run лежит в профиле пользователя: убираем её у всех загруженных профилей
    nsExec::Exec 'powershell -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | ForEach-Object { Remove-ItemProperty -Path (Join-Path $$_.PSPath Software\Microsoft\Windows\CurrentVersion\Run) -Name Bunt -ErrorAction SilentlyContinue }"'
    Pop $R8
  ${EndIf}
!macroend
