import Foundation
import MachO

extension JailbreakCore {
    func checkCallingSystemAPIs() -> [CheckItemResult] {
        if isBypassed() { return [] }
        
        var results: [CheckItemResult] = []
        let keywords = ["substrate", "substitute", "hook", "frida", "roothide", "tweaks", "ellekit", "cydia"]
        
        var foundKeywords: Set<String> = []
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let cStringName = _dyld_get_image_name(i) {
                let imageName = String(cString: cStringName).lowercased()
                for keyword in keywords {
                    if imageName.contains(keyword) {
                        foundKeywords.insert(keyword)
                    }
                }
            }
        }
        
        for keyword in keywords {
            let matched = foundKeywords.contains(keyword)
            results.append(CheckItemResult(
                name: "Keyword: [\(keyword)]",
                isDetected: matched,
                description: matched ? "Matched inside loaded dynamic libraries" : "Not detected in memory"
            ))
        }
        return results
    }
}
