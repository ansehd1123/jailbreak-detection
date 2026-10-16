import Foundation

class JailbreakCore {
    static let shared = JailbreakCore()
    private init() {}

    func runAllChecks() -> [CheckItemResult] {
        var allItems: [CheckItemResult] = []
        allItems.append(contentsOf: checkFileBased())
        allItems.append(contentsOf: checkFilePermissions())
        allItems.append(contentsOf: checkProtocolHandlers())
        allItems.append(contentsOf: checkCallingSystemAPIs())
        allItems.append(contentsOf: checkOpenSSHService())
        return allItems
    }
}
