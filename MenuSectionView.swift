import SwiftUI

struct MenuSectionView: View {
    // ContentView에 정의된 CheckType을 참조
    let onSelect: (ContentView.CheckType) -> Void
    
    var body: some View {
        VStack(spacing: 12) {
            MenuButton(title: "1. File-based Checks", color: .blue) {
                onSelect(.fileBased)
            }
            
            MenuButton(title: "2. Checking File Permissions", color: .blue) {
                onSelect(.filePermissions)
            }
            
            MenuButton(title: "3. Sandbox Integrity Checks", color: .blue) {
                onSelect(.sandboxIntegrity)
            }
            
            MenuButton(title: "4. Debugger Detection", color: .blue) {
                onSelect(.debugging)
            }
        }
        .padding(.horizontal)
    }
}

/// 재사용 가능한 메뉴 버튼 컴포넌트
struct MenuButton: View {
    let title: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding()
                .background(color)
                .foregroundColor(.white)
                .cornerRadius(10)
                .shadow(radius: 2)
        }
    }
}
