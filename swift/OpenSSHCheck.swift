import Foundation
import Darwin

extension JailbreakCore {
    func checkOpenSSHService() -> [CheckItemResult] {
        if isBypassed() { return [] }
        
        var results: [CheckItemResult] = []
        let ports: [in_port_t] = [22, 44, 2222, 222]
        
        for port : in_port_t in ports {
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            var isOpen = false
            if sock >= 0 {
                var addr = sockaddr_in()
                addr.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = port.bigEndian
                addr.sin_addr.s_addr = inet_addr("127.0.0.1")
                let connectResult = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
                close(sock)
                isOpen = (connectResult == 0)
            }
            
            results.append(CheckItemResult(
                name: "Port \(port)",
                isDetected: isOpen,
                description: isOpen ? "Daemon service is listening locally" : "Port closed / unreachable"
            ))
        }
        return results
    }
}
