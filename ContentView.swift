import SwiftUI

struct ContentView: View {
    @State private var resultText: String = "Select a diagnostic check option below to view blacklist items and status."
    @State private var resultColor: Color = .primary
    
    var body: some View {
        VStack(spacing: 15) {
            HeaderView()
            
            // 각 버튼이 case 문을 거치지 않고 직접 해당 검사 함수를 호출합니다.
            ScrollView {
                VStack(spacing: 10) {
                    MenuButton(title: "1. File-based Checks", color: .blue) {
                        executeCheck(title: "1. File-based Checks", results: JailbreakCore.shared.checkFileBased())
                    }
                    MenuButton(title: "2. Checking File Permissions", color: .blue) {
                        executeCheck(title: "2. Checking File Permissions", results: JailbreakCore.shared.checkFilePermissions())
                    }
                    MenuButton(title: "3. Checking Protocol Handlers", color: .blue) {
                        executeCheck(title: "3. Checking Protocol Handlers", results: JailbreakCore.shared.checkProtocolHandlers())
                    }
                    MenuButton(title: "4. Calling System APIs", color: .blue) {
                        executeCheck(title: "4. Calling System APIs", results: JailbreakCore.shared.checkCallingSystemAPIs())
                    }
                    MenuButton(title: "5. OpenSSH service Detection", color: .blue) {
                        executeCheck(title: "5. OpenSSH service Detection", results: JailbreakCore.shared.checkOpenSSHService())
                    }
                    MenuButton(title: "6. Run All Checks (Batch)", color: .purple) {
                        executeCheck(title: "6. Run All Checks (Batch)", results: JailbreakCore.shared.runAllChecks())
                    }
                }
                .padding(.horizontal, 20)
            }
            .frame(maxHeight: 280)
            
            ResultSectionView(text: resultText, color: resultColor)
        }
    }
    
    // 개별 검사 결과를 받아와서 화면에 출력하는 전용 함수
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
