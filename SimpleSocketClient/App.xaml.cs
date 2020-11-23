using System.Windows;

using FormsApplication = System.Windows.Forms.Application;

namespace SimpleSocketClient
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        static App()
        {
            FormsApplication.SetCompatibleTextRenderingDefault(false);
            FormsApplication.EnableVisualStyles();
        }
    }
}
