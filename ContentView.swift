import SwiftUI

struct ContentView: View {
    @State private var resultText: String = "Select a diagnostic check option below to view blacklist items and status."
    @State private var resultColor: Color = .primary
    
    var body: some View {
        VStack(spacing: 15) {
            Text("Advanced Jailbreak Inspector")
                .font(.title2)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
                .padding(.top, 15)
            
            // 진단 메뉴 영역 (1~5번 개별 진단, 6번 전체 진단)
            ScrollView {
                VStack(spacing: 10) {
                    MenuButton(title: "1. File-based Checks", color: .blue) {
                        runSpecificCheck(.fileBased)
                    }
                    MenuButton(title: "2. Checking File Permissions", color: .blue) {
                        runSpecificCheck(.filePermissions)
                    }
                    MenuButton(title: "3. Checking Protocol Handlers", color: .blue) {
                        runSpecificCheck(.protocolHandlers)
                    }
                    MenuButton(title: "4. Calling System APIs", color: .blue) {
                        runSpecificCheck(.systemAPIs)
                    }
                    MenuButton(title: "5. OpenSSH service Detection", color: .blue) {
                        runSpecificCheck(.openSSH)
                    }
                    MenuButton(title: "6. Run All Checks (Batch)", color: .purple) {
                        runSpecificCheck(.all)
                    }
                }
                .padding(.horizontal, 20)
            }
            .frame(maxHeight: 280)
            
            // 결과 출력 영역
            ScrollView {
                Text(resultText)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(resultColor)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .background(Color(UIColor.secondarySystemBackground))
            .cornerRadius(10)
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
    }
    
    enum CheckType {
        case fileBased, filePermissions, protocolHandlers, systemAPIs, openSSH, all
    }
    
    private func runSpecificCheck(_ type: CheckType) {
        resultText = "Analyzing system against criteria...\n"
        resultColor = .primary
        
        let core = JailbreakCore.shared
        var results: [CheckItemResult] = []
        let checkName: String
        
        switch type {
        case .fileBased:
            checkName = "1. File-based Checks"
            results = core.checkFileBased()
        case .filePermissions:
            checkName = "2. Checking File Permissions"
            results = core.checkFilePermissions()
        case .protocolHandlers:
            checkName = "3. Checking Protocol Handlers"
            results = core.checkProtocolHandlers()
        case .systemAPIs:
            checkName = "4. Calling System APIs"
            results = core.checkCallingSystemAPIs()
        case .openSSH:
            checkName = "5. OpenSSH service Detection"
            results = core.checkOpenSSHService()
        case .all:
            checkName = "6. Run All Checks (Batch)"
            results = core.runAllChecks()
        }
        
        let hasThreat = results.contains { $0.isDetected }
        displayResult(isJailbroken: hasThreat, items: results, title: checkName)
    }
    
    private func displayResult(isJailbroken: Bool, items: [CheckItemResult], title: String) {
        var log = "[\(title)]\n\n"
        
        if isJailbroken {
            log += "⚠️ Status: JAILBROKEN (Threat Found)\n\n"
            resultColor = .red
        } else {
            log += "✅ Status: Clean (All Safe)\n\n"
            resultColor = .green
        }
        
        log += "Blacklist / Criteria Evaluation:\n"
        for item in items {
            let badge = item.isDetected ? "[⚠️ DETECTED]" : "[✅ CLEAN]"
            log += " \(badge) \(item.name)\n"
            if !item.description.isEmpty {
                log += "    └─ \(item.description)\n"
            }
        }
        
        resultText = log
    }
}

struct MenuButton: View {
    let title: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.headline)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(color)
                .cornerRadius(8)
        }
    }
}
