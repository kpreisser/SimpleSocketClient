using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;

using FormsTaskDialog = System.Windows.Forms.TaskDialog;
using FormsTaskDialogIcon = System.Windows.Forms.TaskDialogIcon;
using FormsTaskDialogPage = System.Windows.Forms.TaskDialogPage;

namespace SimpleSocketClient
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static readonly IReadOnlyDictionary<string, Encoding> availableEncodings;

        private UiSocketHandler? currentSocketHandler;

        private Paragraph? currentInlineParagraph;

        static MainWindow()
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            var win1252 = Encoding.GetEncoding(1252);
            
            // Don't emit the UTF-8 BOM when using the UTF-8 encoding.
            var utf8 = new UTF8Encoding(false);

            availableEncodings = new Dictionary<string, Encoding>(StringComparer.OrdinalIgnoreCase)
            {
                { win1252.WebName, win1252 },
                { utf8.WebName, utf8 }
            };
        }

        public MainWindow()
        {
            this.InitializeComponent();

            this.cbxProtocol.SelectedItem = this.cbxProtocol.Items[0];
            this.chkSingleLine.IsChecked = true;
        }

        private void UpdateControls()
        {
            this.cbxProtocol.IsEnabled = 
                this.txtHostnameUrl.IsEnabled = 
                this.txtHostnameUrl.IsEnabled = 
                this.cbxBinaryEncoding.IsEnabled =
                this.currentSocketHandler == null;

            this.btnCloseSendChannel.IsEnabled = 
                this.btnSend.IsEnabled =
                this.currentSocketHandler != null;

            bool isWebSocket = ((ComboBoxItem)this.cbxProtocol.SelectedItem).Tag is "websocket";

            this.txtPort.IsEnabled = 
                this.chkUseSsl.IsEnabled = 
                this.cbxSocketMode.IsEnabled =
                this.currentSocketHandler == null && !isWebSocket;

            this.chkIgnoreCertErrors.IsEnabled = 
                this.chkTls10.IsEnabled = 
                this.chkTls11.IsEnabled = 
                this.chkTls12.IsEnabled = 
                this.chkTls13.IsEnabled = 
                this.chkUseSsl.IsEnabled && this.chkUseSsl.IsChecked == true;
        }

        private void HandleCbxProtocolSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            this.UpdateControls();
        }

        private void HandleChkUseSslCheckedUnchecked(object sender, RoutedEventArgs e)
        {
            this.UpdateControls();
        }

        private void HandleBtnConnectClick(object sender, RoutedEventArgs e)
        {
            if (currentSocketHandler == null)
            {
                this.currentInlineParagraph = null;
                this.rtfReceiveDocument.Blocks.Clear();

                try
                {
                    bool isWebSocket = ((ComboBoxItem)this.cbxProtocol.SelectedItem).Tag is "websocket";

                    string host = this.txtHostnameUrl.Text;
                    int port = isWebSocket ? 0 : ushort.Parse(this.txtPort.Text);

                    var addressFamily = isWebSocket ? default(AddressFamily?) : (string)((ComboBoxItem)this.cbxSocketMode.SelectedItem).Tag switch
                    {
                        "dual" => AddressFamily.Unknown,
                        "ipv4" => AddressFamily.InterNetwork,
                        "ipv6" => AddressFamily.InterNetworkV6,
                        _ => throw new InvalidOperationException()
                    };

                    var encoding = availableEncodings[(string)((ComboBoxItem)this.cbxBinaryEncoding.SelectedItem).Tag];

                    bool useSsl = this.chkUseSsl.IsChecked == true;
                    bool ignoreSslCertErrors = this.chkIgnoreCertErrors.IsChecked == true;

                    var sslProtocols = default(SslProtocols);
                    if (this.chkTls10.IsChecked == true)
                        sslProtocols |= SslProtocols.Tls;
                    if (this.chkTls11.IsChecked == true)
                        sslProtocols |= SslProtocols.Tls11;
                    if (this.chkTls12.IsChecked == true)
                        sslProtocols |= SslProtocols.Tls12;
                    if (this.chkTls13.IsChecked == true)
                        sslProtocols |= SslProtocols.Tls13;
               
                    var localClientState = new UiSocketHandler(
                        async (action, token) => await this.Dispatcher.InvokeAsync(
                            action,
                            DispatcherPriority.Normal,
                            token),
                        isWebSocket,
                        host,
                        port,
                        addressFamily,
                        encoding,
                        useSsl,
                        ignoreSslCertErrors,
                        sslProtocols);

                    localClientState.SocketMessage += (s, e) =>
                        this.AddStreamText(e.Text, e.IsMetaText, e.IsSendText);
                    localClientState.ConnectionFinished += (s, e) => this.StopConnection();

                    localClientState.Start();

                    // Creating the connection worked.
                    this.currentSocketHandler = localClientState;

                    this.btnConnect.Content = "Abort";
                    this.UpdateControls();
                }
                catch (Exception ex)
                {
                    FormsTaskDialog.ShowDialog(new WindowInteropHelper(this).Handle, new FormsTaskDialogPage()
                    {
                        Caption = this.Title,
                        Heading = ex.Message,
                        Icon = FormsTaskDialogIcon.Error
                    });
                }
            }
            else
            {
                // Stop the connection.
                this.StopConnection();
            }
        }

        private void HandleBtnSendClick(object sender, RoutedEventArgs e)
        {
            string lineEnding = (string)((ComboBoxItem)this.cbxLineEnding.SelectedItem).Tag;
            string text = this.txtSendText.Text;

            // Replace all line endings with the specified one.
            text = text.Replace("\r\n", "\n").Replace("\n", lineEnding);

            if (this.chkSingleLine.IsChecked == true)
                text += lineEnding;

            this.currentSocketHandler!.Send(text);
            this.txtSendText.Text = string.Empty;
        }

        private void HandleBtnCloseSendChannelClick(object sender, RoutedEventArgs e)
        {
            this.currentSocketHandler!.CloseSendChannel();

            // The send channel is no longer usable, so disable the corresponding controls.
            this.btnCloseSendChannel.IsEnabled = false;
            this.btnSend.IsEnabled = false;
        }

        private void HandleChkSingleLineCheckedChanged(object sender, RoutedEventArgs e)
        {
            this.txtSendText.AcceptsReturn = this.chkSingleLine.IsChecked != true;
        }

        private void HandleTxtSendTextKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && this.chkSingleLine.IsChecked == true && this.btnSend.IsEnabled)
                this.HandleBtnSendClick(sender, e);
        }

        private void StopConnection()
        {
            this.currentSocketHandler!.Stop();
            this.currentSocketHandler = null;

            this.btnConnect.Content = "Connect";
            this.UpdateControls();
        }

        private void AddStreamText(string text, bool isMetaText = false, bool isSendText = false)
        {
            var run = new Run(text);
            if (isMetaText)
                run.Foreground = Brushes.Red;
            else if (isSendText)
                run.Foreground = Brushes.DarkCyan;

            if (isMetaText)
            {
                // Add the next in a new block.
                this.currentInlineParagraph = null;
                this.rtfReceiveDocument.Blocks.Add(new Paragraph(run)
                {
                    Margin = new Thickness()
                });
            }
            else
            {
                // Append the text within the last paragraph, if available.
                if (this.currentInlineParagraph is null)
                {
                    this.currentInlineParagraph = new Paragraph(run)
                    {
                        Margin = new Thickness()
                    };

                    this.rtfReceiveDocument.Blocks.Add(this.currentInlineParagraph);
                }
                else
                {
                    this.currentInlineParagraph.Inlines.Add(run);
                }
            }

            this.rtfReceive.ScrollToEnd();
        }

        private void HandleWindowClosed(object sender, EventArgs e)
        {
            if (this.currentSocketHandler != null)
            {
                this.currentSocketHandler.Stop();
                this.currentSocketHandler = null;
            }
        }
    }
}
