import SwiftUI
import Darwin // 앱 강제 종료(exit)를 위해 Darwin 임포트

struct ContentView: View {
    @State private var resultText: String = "Select a diagnostic check option below to view blacklist items and status."
    @State private var resultColor: Color = .primary
    
    var body: some View {
        VStack(spacing: 15) {
            HeaderView()
            
            // 각 버튼별 독립 액션 연결 (6번만 배치 전용 함수 호출)
            MenuSectionView(
                action1: { executeCheck(title: "1. File-based Checks", results: JailbreakCore.shared.checkFileBased()) },
                action2: { executeCheck(title: "2. Checking File Permissions", results: JailbreakCore.shared.checkFilePermissions()) },
                action3: { executeCheck(title: "3. Checking Protocol Handlers", results: JailbreakCore.shared.checkProtocolHandlers()) },
                action4: { executeCheck(title: "4. Calling System APIs", results: JailbreakCore.shared.checkCallingSystemAPIs()) },
                action5: { executeCheck(title: "5. OpenSSH service Detection", results: JailbreakCore.shared.checkOpenSSHService()) },
                action6: { executeBatchCheck() }
            )
            
            ResultSectionView(text: resultText, color: resultColor)
        }
    }
    
    // 1~5번 개별 검사 결과 출력 함수 (상세 사유 표시)
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
    
    // 6번 전체 검사(Batch) 전용 함수: 탐지 시 사유 출력 없이 즉시 종료
    private func executeBatchCheck() {
        let results = JailbreakCore.shared.runAllChecks()
        let hasThreat = results.contains { $0.isDetected }
        
        if hasThreat {
            // 탈옥 탐지 시 사유를 보여주지 않고 즉시 앱 종료 (exit(0))
            exit(0)
        } else {
            let title = "6. Run All Checks (Batch)"
            var log = "[\(title)]\n\n"
            log += "✅ Status: Clean (All Safe)\n\n"
            log += "Blacklist / Criteria Evaluation:\n"
            for item in results {
                log += " [✅ CLEAN] \(item.name)\n"
                if !item.description.isEmpty {
                    log += "    └─ \(item.description)\n"
                }
            }
            resultColor = .green
            resultText = log
        }
    }
}
