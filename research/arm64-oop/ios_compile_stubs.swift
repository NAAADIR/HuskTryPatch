// SPDX-License-Identifier: GPL-2.0-or-later
// Only for type-checking the diagnostic view without linking the entire app.
import SwiftUI
final class QemuRunner: ObservableObject {
    static let shared = QemuRunner()
    var isRunning = false
}
enum JITBootstrap { static func prewarm() -> Bool { true } }
