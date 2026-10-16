import Foundation

extension JailbreakCore {
    func checkFilePermissions() -> [CheckItemResult] {
        var results: [CheckItemResult] = []
        
        let testPath = "/private/jb_test_\(UUID().uuidString.prefix(6))"
        let isWritable = FileManager.default.createFile(atPath: testPath, contents: Data("test".utf8), attributes: nil)
        if isWritable {
            try? FileManager.default.removeItem(atPath: testPath)
        }
        results.append(CheckItemResult(
            name: "Sandbox Write Escape Test",
            isDetected: isWritable,
            description: isWritable ? "Successfully wrote to restricted private path" : "Blocked by sandbox (Normal)"
        ))
        
        var s = stat()
        let isSymlink = (lstat("/var/jb", &s) == 0) && ((s.st_mode & S_IFMT) == S_IFLNK)
        results.append(CheckItemResult(
            name: "Symlink Check (/var/jb)",
            isDetected: isSymlink,
            description: isSymlink ? "/var/jb is a symbolic link (Rootless jailbreak)" : "Clean or does not exist"
        ))
        
        return results
    }
}
