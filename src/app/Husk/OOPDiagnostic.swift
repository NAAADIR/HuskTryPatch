// SPDX-License-Identifier: GPL-2.0-or-later
#if HUSK_OOP_IOS_DIAG
import SwiftUI

struct OOPDiagnosticSection: View {
    @ObservedObject private var runner = QemuRunner.shared
    @ObservedObject private var store = TranslationLayerStore.shared
    @State private var result: String?
    @State private var realResult: String?
    @State private var testingReal = false
    /// Opt-in: the next Brave Frontier V20 launch runs libgame.so out of place (husk-oop-launch.c).
    @AppStorage("huskOOPGame") private var oopGame = false

    var body: some View {
        Section("Developer Diagnostic") {
            Toggle("Run Brave Frontier V20 out of place", isOn: $oopGame)
            if oopGame { Text("Next launch only uses the out-of-place backend; it fails rather than run in place. Restart Husk first.").font(.footnote) }
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
                result = ok ? "Passed. Restart Husk before starting a console or game."
                            : "Failed. See husk.log; restart Husk before a console or game."
            }
            .disabled(runner.isRunning || testingReal)
            if let result { Text(result).font(.footnote) }
            Button("Run real Brave Frontier ARM64 test") {
                guard !runner.isRunning, JITBootstrap.prewarm() else {
                    husk_oop_real_preflight_fail(0)
                    realResult = "JIT is unavailable or Android is running."
                    return
                }
                let packagePaths = store.apps.filter { $0.packageName == "sg.gumi.bravefrontier" }.flatMap { $0.apks }
                let allPaths = store.apps.flatMap { $0.apks }
                guard !allPaths.isEmpty else {
                    husk_oop_real_preflight_fail(1)
                    realResult = "Brave Frontier is not installed in Husk's app library."
                    return
                }
                let angle = (Bundle.main.privateFrameworksPath ?? "") + "/libANGLE-shared.dylib"
                testingReal = true
                runner.oopDiagnosticActive = true
                realResult = "Running; this may take a while."
                Task {
                    let ok = await Task.detached(priority: .userInitiated) {
                        let candidates = packagePaths + allPaths.filter { !packagePaths.contains($0) }
                        let found = candidates.first { candidate in candidate.withCString { husk_oop_real_apk_matches($0) != 0 } }
                        guard let path = found ?? packagePaths.first else {
                            husk_oop_real_preflight_fail(1)
                            return false
                        }
                        return path.withCString { apk in angle.withCString { egl in husk_oop_real_run(apk, egl, nil) != 0 } }
                    }.value
                    runner.oopDiagnosticActive = false
                    testingReal = false
                    realResult = ok ? "Passed. See HUSK-OOP-REAL in the log."
                                    : "Failed. See HUSK-OOP-REAL in the log."
                }
            }
            .disabled(runner.isRunning || testingReal)
            if let realResult { Text(realResult).font(.footnote) }
            Text("Each diagnostic can claim the allocator once per Husk process. Fully restart Husk before rerunning a diagnostic or starting a console or game.")
                .font(.footnote)
        }
    }
}
#endif
