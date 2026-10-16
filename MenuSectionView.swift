import SwiftUI

struct MenuSectionView: View {
    let action1: () -> Void
    let action2: () -> Void
    let action3: () -> Void
    let action4: () -> Void
    let action5: () -> Void
    let action6: () -> Void
    
    var body: some View {
        ScrollView {
            VStack(spacing: 10) {
                MenuButton(title: "1. File-based Checks", color: .blue, action: action1)
                MenuButton(title: "2. Checking File Permissions", color: .blue, action: action2)
                MenuButton(title: "3. Checking Protocol Handlers", color: .blue, action: action3)
                MenuButton(title: "4. Calling System APIs", color: .blue, action: action4)
                MenuButton(title: "5. OpenSSH service Detection", color: .blue, action: action5)
                MenuButton(title: "6. Run All Checks (Batch)", color: .purple, action: action6)
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
