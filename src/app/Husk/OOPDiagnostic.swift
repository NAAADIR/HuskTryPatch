// SPDX-License-Identifier: GPL-2.0-or-later
#if HUSK_OOP_IOS_DIAG
import SwiftUI

struct OOPDiagnosticSection: View {
    @ObservedObject private var runner = QemuRunner.shared
    @State private var result: String?

    var body: some View {
        Section("Developer Diagnostic") {
            Button("Run out-of-place ARM64 test") {
                guard !runner.isRunning, JITBootstrap.prewarm() else {
                    husk_oop_ios_preflight_fail(0)
                    result = "JIT is unavailable or Android is running."
                    return
                }
                guard let path = Bundle.main.path(forResource: "husk-oop-fixture", ofType: "bin") else {
                    husk_oop_ios_preflight_fail(1)
                    result = "Diagnostic fixture is missing."
                    return
                }
                let ok = path.withCString { husk_oop_ios_run($0) != 0 }
                result = ok ? "Passed. Restart Husk before starting a console session."
                            : "Failed. See husk.log; restart Husk before a console session."
            }
            .disabled(runner.isRunning)
            if let result { Text(result).font(.footnote) }
        }
    }
}
#endif
