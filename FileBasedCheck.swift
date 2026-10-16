import Foundation

extension JailbreakCore {
    func checkFileBased() -> [CheckItemResult] {
        if isBypassed() { return [] }
        
        var results: [CheckItemResult] = []
        let paths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/var/jb/usr/bin/bash",
            "/var/jb/Applications/Sileo.app",
            "/etc/apt"
        ]
        
        for path in paths {
            let exists = FileManager.default.fileExists(atPath: path) || access(path, F_OK) == 0
            results.append(CheckItemResult(
                name: path,
                isDetected: exists,
                description: exists ? "Blacklist artifact found on disk" : "Not found"
            ))
        }
        return results
    }
}
