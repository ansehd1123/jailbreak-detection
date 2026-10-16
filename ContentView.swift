import SwiftUI

struct ContentView: View {
    @State private var resultText: String = "Select a diagnostic check option below to view blacklist items and status."
    @State private var resultColor: Color = .primary
    
    enum CheckType {
        case fileBased, filePermissions, protocolHandlers, systemAPIs, openSSH, all
    }
    
    var body: some View {
        VStack(spacing: 15) {
            HeaderView()
            
            MenuSectionView { type in
                runSpecificCheck(type)
            }
            
            ResultSectionView(text: resultText, color: resultColor)
        }
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
