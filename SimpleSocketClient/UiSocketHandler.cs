using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SimpleSocketClient
{
    internal class UiSocketHandler
    {
        // Throw on invalid bytes for easier debugging of incorrect implementations.
        private static readonly Encoding webSocketTextMessageEncoding =
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        private readonly Func<Action, CancellationToken, Task> invokeAsyncFunc;

        private readonly bool isWebsocket;

        private readonly string? host;

        private readonly int port;

        private readonly AddressFamily addressFamily;

        private readonly Uri? webSocketUrl;

        private readonly Encoding binaryMessageEncoding;

        private readonly bool useSsl;

        private readonly bool ignoreSslCertErrors;

        private readonly SslProtocols sslProtocols;

        private readonly CancellationTokenSource ctSource = new CancellationTokenSource(); // TODO: Create on demand

        private readonly ConcurrentQueue<(string? text, bool closeSend)> sendQueue =
            new ConcurrentQueue<(string?, bool)>();

        private readonly SemaphoreSlim sendQueueSemaphore = new SemaphoreSlim(0); // TODO: Create on demand

        private Task? receiveTask;

        public UiSocketHandler(
            Func<Action, CancellationToken, Task> invokeAsyncFunc,
            bool isWebsocket,
            string host,
            int port,
            AddressFamily? addressFamily,
            Encoding binaryMessageEncoding,
            bool useSsl,
            bool ignoreSslCertErrors,
            SslProtocols sslProtocols)
        {
            this.invokeAsyncFunc = invokeAsyncFunc;
            this.isWebsocket = isWebsocket;

            if (isWebsocket)
            {
                this.webSocketUrl = new Uri(host);
            }
            else
            {
                this.host = host;
                this.port = port;
                this.addressFamily = addressFamily ?? throw new ArgumentNullException(nameof(addressFamily));
            }

            this.binaryMessageEncoding = binaryMessageEncoding;
            this.useSsl = useSsl;
            this.ignoreSslCertErrors = ignoreSslCertErrors;
            this.sslProtocols = sslProtocols;

        }

        public event EventHandler<SocketMessageEventArgs>? SocketMessage;

        public event EventHandler? ConnectionFinished;

        private static string FormatSslProtocol(SslProtocols protocol)
        {
            return protocol switch
            {
                SslProtocols.Tls => "TLS 1.0",
                SslProtocols.Tls11 => "TLS 1.1",
                SslProtocols.Tls12 => "TLS 1.2",
                SslProtocols.Tls13 => "TLS 1.3",
                var other => other.ToString()
            };
        }

        public void Start()
        {
            if (this.isWebsocket)
            {
                // Use Uri.AbsoluteUri instead of Uri.ToString() as the latter unescapes
                // characters and thus could return a string e.g. with spaces and non-ASCII
                // characters.
                this.OnSocketMessage(new SocketMessageEventArgs(
                    $"Connecting to WebSocket URL '{this.webSocketUrl!.AbsoluteUri}'…",
                    isMetaText: true));
            }
            else
            {
                this.OnSocketMessage(new SocketMessageEventArgs(
                    $"Connecting to '{this.host}:{this.port}'…",
                    isMetaText: true));
            }

            // Start the receive task.
            this.receiveTask = this.isWebsocket ?
                Task.Run(this.RunWebSocketReceiveTaskAsync) :
                Task.Run(this.RunTcpReceiveTaskAsync);
        }

        public void Stop()
        {
            // Cancel the token, which ensures the worker tasks will do no more updates in the UI
            // and will cancel outstanding I/O operations.
            this.ctSource.Cancel();

            // Now do a blocking wait on the receive task, to ensure the socket worker activity
            // is finished before we continue.
            this.receiveTask!.GetAwaiter().GetResult();

            this.OnSocketMessage(new SocketMessageEventArgs(
                "Connection closed/aborted.",
                isMetaText: true));

            this.ctSource.Dispose();
            this.sendQueueSemaphore.Dispose();
        }

        public void Send(string text)
        {
            this.sendQueue.Enqueue((text, false));
            this.sendQueueSemaphore.Release();
        }

        public void CloseSendChannel()
        {
            this.sendQueue.Enqueue((null, true));
            this.sendQueueSemaphore.Release();
        }

        protected virtual void OnSocketMessage(SocketMessageEventArgs e)
        {
            this.SocketMessage?.Invoke(this, e);
        }

        protected virtual void OnConnectionFinished(EventArgs e)
        {
            this.ConnectionFinished?.Invoke(this, e);
        }

        private async Task RunTcpReceiveTaskAsync()
        {
            try
            {
                using var client = new TcpClient(this.addressFamily);
                await client.ConnectAsync(this.host!, this.port, this.ctSource.Token);
                
                // After the socket is connected, configure it to disable the Nagle
                // algorithm and delayed ACKs (and maybe enable TCP keep-alive in the
                // future).
                SocketConfigurator.ConfigureSocket(client.Client);

                // Create the NetworkStream without owning the socket, so that disposing
                // the stream (e.g. when disposing the SslStream) doesn't close the socket
                // (as we want to close it manually using a RST).
                Stream clientStream = new NetworkStream(client.Client, ownsSocket: false);

                // For better performance, we don't wait for the initial invokes to complete
                // before continuing.
                var remoteEndpoint = client.Client.RemoteEndPoint;
                _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                    $"TCP connection established to '{remoteEndpoint}'." + (this.useSsl ? " Negotiating TLS…" : ""),
                    isMetaText: true)));

                if (this.useSsl)
                {
                    var sslStream = new SslStream(clientStream);
                    try
                    {
                        await sslStream.AuthenticateAsClientAsync(
                            new SslClientAuthenticationOptions()
                            {
                                TargetHost = host,
                                EnabledSslProtocols = this.sslProtocols,
                                RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                                {
                                    if (this.ignoreSslCertErrors)
                                        return true;

                                    return sslPolicyErrors == SslPolicyErrors.None;
                                }
                            },
                            this.ctSource.Token);

                        var sslProtocol = sslStream.SslProtocol;
                        var cipherSuite = sslStream.NegotiatedCipherSuite;
                        var remoteCertificate = sslStream.RemoteCertificate!;

                        _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                            $"TLS negotiated. Protocol: {FormatSslProtocol(sslProtocol)}, CipherSuite: {cipherSuite}, Certificate SHA-1 Hash: {remoteCertificate.GetCertHashString()} (issued by: {remoteCertificate.Issuer}; not after: {remoteCertificate.GetExpirationDateString()})",
                            isMetaText: true)));
                    }
                    catch
                    {
                        await sslStream.DisposeAsync();

                        // Reset the connection.
                        client.Client.Close(0);

                        throw;
                    }

                    clientStream = sslStream;
                }

                await using (clientStream)
                {
                    // Start the send task. We will wait for it to finish before disposing
                    // of the TcpClient.
                    var sendTask = Task.Run(async () =>
                    {
                        try
                        {
                            while (true)
                            {
                                await this.sendQueueSemaphore.WaitAsync(this.ctSource.Token);
                                if (!this.sendQueue.TryDequeue(out var tuple))
                                    throw new InvalidOperationException();

                                // Note: When invoking actions in the UI thread we don't
                                // need to wait for them to finish, since they were caused
                                // by ourselves and not from a remote party.
                                if (tuple.closeSend)
                                {
                                    // Close the send channel.
                                    // We need to do the operation after the logging, as
                                    // otherwise it could happen that the receive worker
                                    // task logs a message that is a result of our operation
                                    // before we actually logged it.
                                    _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                                        $"Send Channel closing.",
                                        isMetaText: true)));

                                    if (clientStream is SslStream sslStream)
                                    {
                                        // Properly shutdown the send channel of the SSL/TLS
                                        // connection, as otherwise the remote would have to
                                        // treat it as error (to protect from spoofed FIN
                                        // packets).
                                        // TODO: Why can't we pass a CancellationToken here?
                                        await sslStream.ShutdownAsync();
                                    }

                                    client.Client.Shutdown(SocketShutdown.Send);
                                    break;
                                }
                                else
                                {
                                    // Send the text.
                                    int byteCount = this.binaryMessageEncoding.GetByteCount(tuple.text!);
                                    var buffer = ArrayPool<byte>.Shared.Rent(byteCount);
                                    byteCount = this.binaryMessageEncoding.GetBytes(tuple.text, buffer);
                                    var memory = buffer.AsMemory()[..byteCount];

                                    // Because we don't wait for the UI action and the buffer might
                                    // be reused after returning it, we need to create the string here,
                                    // not in the action invoked in the UI thread.
                                    string text = this.binaryMessageEncoding.GetString(memory.Span);

                                    _ = this.InvokeAsync(() =>
                                    {
                                        // Decode the bytes back to a string (instead of simply
                                        // using the original string), to ensure we display the
                                        // characters as they would be decoded when receiving them
                                        // (e.g. when using characters outside of the encoding's
                                        // range).
                                        this.OnSocketMessage(new SocketMessageEventArgs(
                                            text,
                                            isSendText: true));
                                    });

                                    await clientStream.WriteAsync(
                                        memory,
                                        this.ctSource.Token);

                                    await clientStream.FlushAsync(this.ctSource.Token);

                                    ArrayPool<byte>.Shared.Return(buffer);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                                $"Error when sending data: " + ex.Message,
                                isMetaText: true)));
                        }
                    });

                    try
                    {
                        // Create a reader using the specified encoding. Note that when using
                        // a multibyte encoding like UTF-8, we might not immediately display
                        // received text after receiving bytes (in case the character encoding
                        // sequence is not finished).
                        using (var streamReader = new StreamReader(
                            clientStream,
                            this.binaryMessageEncoding,
                            detectEncodingFromByteOrderMarks: false,
                            leaveOpen: true))
                        {
                            var receiveBuffer = new char[32768];
                            int read;

                            while ((read = await streamReader.ReadAsync(
                                receiveBuffer,
                                this.ctSource.Token))
                                > 0)
                            {
                                string text = new string(receiveBuffer, 0, read);

                                // We should wait here until the UI thread completed the invoked
                                // action, to ensure we don't receive faster than the UI thread can
                                // process the received data.
                                await this.InvokeAsync(() =>
                                {
                                    this.OnSocketMessage(new SocketMessageEventArgs(text));
                                });
                            }
                        }

                        _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                            $"Receive Channel closed.",
                            isMetaText: true)));

                    }
                    catch (Exception ex)
                    {
                        try
                        {
                            _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                                $"Error when receiving data: " + ex.Message,
                                isMetaText: true)));
                        }
                        catch (OperationCanceledException)
                        {
                            // Ignore
                        }
                    }
                    finally
                    {
                        await sendTask;

                        // Reset the connection.
                        client.Client.Close(0);
                    }
                }
            }
            catch (Exception ex)
            {
                try
                {
                    _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                        $"Error when establishing connection: " + ex.Message,
                        isMetaText: true)));
                }
                catch (OperationCanceledException)
                {
                    // Ignore
                }
            }
            finally
            {
                // Raise the event that the connection was stopped. We mustn't wait for it to
                // complete because the UI thread will normally call Stop() which in turn
                // will wait for the receive task to finish, which would cause a deadlock
                // because even though Stop() cancels the CancellationToken that we pass
                // to Dispatcher.InvokeAsync(), the action is already being run and so the
                // operation can no longer be canceled.
                _ = this.InvokeAsync(() => this.OnConnectionFinished(EventArgs.Empty));
            }
        }

        private async Task RunWebSocketReceiveTaskAsync()
        {
            // Limit the message size to 100 MiB.
            const int maxMessageSize = 100 * 1024 * 1024;

            try
            {
                using var webSocket = new ClientWebSocket();
                await webSocket.ConnectAsync(this.webSocketUrl!, this.ctSource.Token);

                // For better performance, we don't wait for the initial invokes to complete
                // before continuing.
                _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                    $"WebSocket connection established.",
                    isMetaText: true)));
                    
                // Start the send task. We will wait for it to finish before disposing
                // of the TcpClient.
                var sendTask = Task.Run(async () =>
                {
                    try
                    {
                        while (true)
                        {
                            await this.sendQueueSemaphore.WaitAsync(this.ctSource.Token);
                            if (!this.sendQueue.TryDequeue(out var tuple))
                                throw new InvalidOperationException();

                            // Note: When invoking actions in the UI thread we don't
                            // need to wait for them to finish, since they were caused
                            // by ourselves and not from a remote party.
                            if (tuple.closeSend)
                            {
                                // Close the send channel.
                                // We need to do the operation after the logging, as
                                // otherwise it could happen that the receive worker
                                // task logs a message that is a result of our operation
                                // before we actually logged it.
                                _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                                    $"Send Channel closing.",
                                    isMetaText: true)));

                                await webSocket.CloseOutputAsync(
                                    WebSocketCloseStatus.NormalClosure,
                                    null,
                                    this.ctSource.Token);

                                break;
                            }
                            else
                            {
                                // Send the text.
                                _ = this.InvokeAsync(() =>
                                {
                                    this.OnSocketMessage(new SocketMessageEventArgs(
                                        $"Sending WebSocket message (type: Text):",
                                        isMetaText: true));

                                    this.OnSocketMessage(new SocketMessageEventArgs(
                                        tuple.text!,
                                        isSendText: true));
                                });

                                int byteCount = webSocketTextMessageEncoding.GetByteCount(tuple.text!);
                                var buffer = ArrayPool<byte>.Shared.Rent(byteCount);
                                byteCount = webSocketTextMessageEncoding.GetBytes(tuple.text, buffer);
                                var memory = new Memory<byte>(buffer, 0, byteCount);

                                await webSocket.SendAsync(
                                    memory,
                                    WebSocketMessageType.Text,
                                    endOfMessage: true,
                                    this.ctSource.Token);

                                ArrayPool<byte>.Shared.Return(buffer);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                            $"Error when sending data: " + ex.Message,
                            isMetaText: true)));
                    }
                });

                try
                {
                    var receiveBuffer = new byte[32768];

                    // Use a MemoryStream to read a complete message.
                    using var ms = new MemoryStream();
                    while (true)
                    {
                        var readResult = await webSocket.ReceiveAsync(
                            (Memory<byte>)receiveBuffer,
                            this.ctSource.Token);

                        if (readResult.MessageType == WebSocketMessageType.Close)
                            break;

                        ms.Write(receiveBuffer.AsSpan()[..readResult.Count]);

                        if (ms.Length > maxMessageSize)
                            throw new InvalidOperationException(
                                $"The WebSocket message exceeds the size of {maxMessageSize / 1024 / 1024} MiB.");

                        if (readResult.EndOfMessage)
                        {
                            if (!ms.TryGetBuffer(out var streamBuffer))
                                throw new InvalidOperationException(); // Should never happen

                            string resultText;
                            if (readResult.MessageType == WebSocketMessageType.Text)
                            {
                                // Text message are always encoded as UTF-8.
                                resultText = webSocketTextMessageEncoding.GetString(streamBuffer);
                            }
                            else
                            {
                                resultText = this.binaryMessageEncoding.GetString(streamBuffer);
                            }

                            // Reset the stream for the next message.
                            ms.Seek(0, SeekOrigin.Begin);
                            ms.SetLength(0);

                            // We should wait here until the UI thread completed the invoked
                            // action, to ensure we don't receive faster than the UI thread can
                            // process the received data.
                            await this.InvokeAsync(() =>
                            {
                                this.OnSocketMessage(new SocketMessageEventArgs(
                                    $"Received WebSocket message (type: {readResult.MessageType}):",
                                    true));
                                this.OnSocketMessage(new SocketMessageEventArgs(resultText));
                            });
                        }
                    }

                    _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                        $"Receive Channel closed.",
                        isMetaText: true)));

                }
                catch (Exception ex)
                {
                    try
                    {
                        _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                            $"Error when receiving data: " + ex.Message,
                            isMetaText: true)));
                    }
                    catch (OperationCanceledException)
                    {
                        // Ignore
                    }
                }
                finally
                {
                    await sendTask;
                }
            }
            catch (Exception ex)
            {
                try
                {
                    _ = this.InvokeAsync(() => this.OnSocketMessage(new SocketMessageEventArgs(
                        $"Error when establishing connection: " + ex.Message,
                        isMetaText: true)));
                }
                catch (OperationCanceledException)
                {
                    // Ignore
                }
            }
            finally
            {
                // Raise the event that the connection was stopped. We mustn't wait for it to
                // complete because the UI thread will normally call Stop() which in turn
                // will wait for the receive task to finish, which would cause a deadlock
                // because even though Stop() cancels the CancellationToken that we pass
                // to Dispatcher.InvokeAsync(), the action is already being run and so the
                // operation can no longer be canceled.
                _ = this.InvokeAsync(() => this.OnConnectionFinished(EventArgs.Empty));
            }
        }

        private Task InvokeAsync(Action action)
        {
            // Specify the CancellationToken on InvokeAsync, so that the call returns once
            // the token is cancelled. That way, we can do a blocking wait on the receive
            // task when we want to cancel the connection without causing a deadlock.
            return this.invokeAsyncFunc(
                () =>
                {
                    // The UI can cancel the connection with the cancellation token. Therefore,
                    // every time we invoke an action in the UI thread, we mustn't do anything
                    // if cancellation is requested. However, this check shouldn't be necessary
                    // if the Dispatcher implementation handles this.
                    if (this.ctSource.Token.IsCancellationRequested)
                        return;

                    action();
                },
                this.ctSource.Token);
        }
    }

    internal struct SocketMessageEventArgs
    {
        public SocketMessageEventArgs(string text, bool isMetaText = false, bool isSendText = false)
        {
            this.Text = text;
            this.IsMetaText = isMetaText;
            this.IsSendText = isSendText;
        }

        public string Text { get; }

        public bool IsMetaText { get; }

        public bool IsSendText { get; }
    }
}
