import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class MyAiScanner implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("GeminiScanner");

        AiSettingsTab settingsTab = new AiSettingsTab(api);
        api.userInterface().registerSuiteTab("GeminiScanner", settingsTab.createTab());

        EndpointMenu endpointMenu = new EndpointMenu(api, settingsTab);
        api.userInterface().registerContextMenuItemsProvider(endpointMenu);

        AiScannerCheck scannerCheck = new AiScannerCheck(api, settingsTab);
        api.scanner().registerScanCheck(scannerCheck);

        api.logging().logToOutput("GeminiScanner loaded successfully.");
    }
}