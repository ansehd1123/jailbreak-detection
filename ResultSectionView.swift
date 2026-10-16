import SwiftUI

struct ResultSectionView: View {
    let text: String
    let color: Color
    
    var body: some View {
        ScrollView {
            Text(text)
                .font(.system(.body, design: .monospaced))
                .foregroundColor(color)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .background(Color(UIColor.secondarySystemBackground))
        .cornerRadius(10)
        .padding(.horizontal, 20)
        .padding(.bottom, 20)
    }
}
