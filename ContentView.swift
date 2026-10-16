import SwiftUI

struct ContentView: View {
    @State private var resultText: String = "Select a diagnostic check option below to view blacklist items and status."
    @State private var resultColor: Color = .primary
    
    var body: some View {
        VStack(spacing: 15) {
            HeaderView()
            
            // 각 버튼을 독립적인 액션으로 연결합니다.
            MenuSectionView(
                action1: { executeCheck(title: "1. File-based Checks", results: JailbreakCore.shared.checkFileBased()) },
                action2: { executeCheck(title: "2. Checking File Permissions", results: JailbreakCore.shared.checkFilePermissions()) },
                action3: { executeCheck(title: "3. Checking Protocol Handlers", results: JailbreakCore.shared.checkProtocolHandlers()) },
                action4: { executeCheck(title: "4. Calling System APIs", results: JailbreakCore.shared.checkCallingSystemAPIs()) },
                action5: { executeCheck(title: "5. OpenSSH service Detection", results: JailbreakCore.shared.checkOpenSSHService()) },
                action6: { executeCheck(title: "6. Run All Checks (Batch)", results: JailbreakCore.shared.runAllChecks()) }
            )
            
            ResultSectionView(text: resultText, color: resultColor)
        }
    }
    
    private func executeCheck(title: String, results: [CheckItemResult]) {
        let hasThreat = results.contains { $0.isDetected }
        var log = "[\(title)]\n\n"
        
        if hasThreat {
            log += "⚠️ Status: JAILBROKEN (Threat Found)\n\n"
            resultColor = .red
        } else {
            log += "✅ Status: Clean (All Safe)\n\n"
            resultColor = .green
        }
        
        log += "Blacklist / Criteria Evaluation:\n"
        for item in results {
            let badge = item.isDetected ? "[⚠️ DETECTED]" : "[✅ CLEAN]"
            log += " \(badge) \(item.name)\n"
            if !item.description.isEmpty {
                log += "    └─ \(item.description)\n"
            }
        }
        
        resultText = log
    }
}
