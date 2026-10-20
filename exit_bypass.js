setTimeout(function() {
    var exitPtr = Module.findExportByName(null, "exit");
    if (exitPtr) {
        // Interceptor.replace를 사용하여 exit 함수를 무력화합니다.
        // 강제 종료 대신 빈 함수로 대체되어 앱이 종료되지 않고 정상 흐름으로 돌아갑니다.
        Interceptor.replace(exitPtr, new NativeCallback(function(status) {
            console.log("[+] Successfully bypassed exit(" + status + ")! Process survived.");
        }, 'void', ['int']));
        
        console.log("[+] exit() successfully neutralized with Interceptor.replace.");
    } else {
        console.log("[-] Failed to find exit export.");
    }
}, 1000);
