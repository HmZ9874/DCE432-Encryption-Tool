namespace DCE432;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        var english = System.Globalization.CultureInfo.GetCultureInfo("en-US");
        System.Globalization.CultureInfo.DefaultThreadCurrentCulture = english;
        System.Globalization.CultureInfo.DefaultThreadCurrentUICulture = english;
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
