import Foundation

class JailbreakCore {
    static let shared = JailbreakCore()
    private init() {}

    @inline(never)
    func checkBypassFlag() -> Int {
        return 0 // <-- 패치 포인트: 0을 1로 변경
    }

    func isBypassed() -> Bool {
        return checkBypassFlag() == 1
    }

    func runAllChecks() -> [CheckItemResult] {
        if isBypassed() { return [] }
        
        var allItems: [CheckItemResult] = []
        allItems.append(contentsOf: checkFileBased())
        allItems.append(contentsOf: checkFilePermissions())
        allItems.append(contentsOf: checkProtocolHandlers())
        allItems.append(contentsOf: checkCallingSystemAPIs())
        allItems.append(contentsOf: checkOpenSSHService())
        return allItems
    }
}
