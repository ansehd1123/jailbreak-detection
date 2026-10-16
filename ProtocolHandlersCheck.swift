import UIKit

extension JailbreakCore {
    func checkProtocolHandlers() -> [CheckItemResult] {
        if isBypassed() { return [] }
        
        var results: [CheckItemResult] = []
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://", "activator://"]
        
        for scheme in schemes {
            let canOpen: Bool
            if let url = URL(string: scheme) {
                canOpen = UIApplication.shared.canOpenURL(url)
            } else {
                canOpen = false
            }
            results.append(CheckItemResult(
                name: scheme,
                isDetected: canOpen,
                description: canOpen ? "Registered app responded to URL scheme" : "Not registered"
            ))
        }
        return results
    }
}
