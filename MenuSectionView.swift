import SwiftUI

struct MenuSectionView: View {
    let onSelect: (ContentView.CheckType) -> Void
    
    var body: some View {
        ScrollView {
            VStack(spacing: 10) {
                MenuButton(title: "1. File-based Checks", color: .blue) {
                    onSelect(.fileBased)
                }
                MenuButton(title: "2. Checking File Permissions", color: .blue) {
                    onSelect(.filePermissions)
                }
                MenuButton(title: "3. Checking Protocol Handlers", color: .blue) {
                    onSelect(.protocolHandlers)
                }
                MenuButton(title: "4. Calling System APIs", color: .blue) {
                    onSelect(.systemAPIs)
                }
                MenuButton(title: "5. OpenSSH service Detection", color: .blue) {
                    onSelect(.openSSH)
                }
                MenuButton(title: "6. Run All Checks (Batch)", color: .purple) {
                    onSelect(.all)
                }
            }
            .padding(.horizontal, 20)
        }
        .frame(maxHeight: 280)
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
