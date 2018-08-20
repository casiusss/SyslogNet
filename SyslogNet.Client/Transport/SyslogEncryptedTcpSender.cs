using System;
using System.Diagnostics;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace SyslogNet.Client.Transport
{
	public class SyslogEncryptedTcpSender : SyslogTcpSender
	{
		protected int IOTimeout;
		public Boolean IgnoreTLSChainErrors { get; private set; }

		protected MessageTransfer _messageTransfer;
		public override MessageTransfer messageTransfer
		{
			get { return _messageTransfer; }
			set
			{
				if (!value.Equals(MessageTransfer.OctetCounting) && transportStream is SslStream)
				{
					throw new SyslogTransportException("Non-Transparent-Framing can not be used with TLS transport");
				}

				_messageTransfer = value;
			}
		}

		public SyslogEncryptedTcpSender(string hostname, int port, int timeout = Timeout.Infinite, bool ignoreChainErrors = false) : base(hostname, port)
		{
			IOTimeout = timeout;
			IgnoreTLSChainErrors = ignoreChainErrors;
			startTLS();
		}

		public override void Reconnect()
		{
			base.Reconnect();
			startTLS();
		}

		private void startTLS()
		{
			transportStream = new SslStream(tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate))
			{
				ReadTimeout = IOTimeout,
				WriteTimeout = IOTimeout
			};
		    string certFile = @"C:\Users\9I00014\Development\IHE\client-public-private.pem";
		    
            X509Certificate2 cert = new X509Certificate2(certFile);
		    X509Certificate2 cert2 = new X509Certificate2(@"C:\Users\9I00014\Development\IHE\gss-gevko-ca.der");
		    X509Certificate2Collection certificateCollection = new X509Certificate2Collection();
		    certificateCollection.Add(cert);
		    certificateCollection.Add(cert2);
			// According to RFC 5425 we MUST support TLS 1.2, but this protocol version only implemented in framework 4.5 and Windows Vista+...
			((SslStream)transportStream).AuthenticateAsClient(
				hostname,
				certificateCollection,
				System.Security.Authentication.SslProtocols.Tls12,
				false
			);

			if (!((SslStream)transportStream).IsEncrypted)
				throw new SecurityException("Could not establish an encrypted connection");

			messageTransfer = MessageTransfer.OctetCounting;
		}

		private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
		    return true;
		    try
		    {
		        String CA_FILE = @"C:\Users\9I00014\Development\IHE\gss-gevko-ca.der";
		        X509Certificate2 ca = new X509Certificate2(CA_FILE);

		        X509Chain chain2 = new X509Chain();
		        chain2.ChainPolicy.ExtraStore.Add(ca);

		        // Check all properties
		        chain2.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

		        // This setup does not have revocation information
		        chain2.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

		        // Build the chain
		        chain2.Build(new X509Certificate2(certificate));

		        // Are there any failures from building the chain?
		        if (chain2.ChainStatus.Length == 0)
		            return true;

		        // If there is a status, verify the status is NoError
		        bool result = chain2.ChainStatus[0].Status == X509ChainStatusFlags.NoError;
		        Debug.Assert(result == true);

		        return result;
		    }

		    catch (Exception ex)
		    {
		        Console.WriteLine(ex);
		    }

			//if (sslPolicyErrors == SslPolicyErrors.None || (IgnoreTLSChainErrors && sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors))
			//	return true;

			//CertificateErrorHandler(String.Format("Certificate error: {0}", sslPolicyErrors));
			return false;
		}

		// Quick and nasty way to avoid logging framework dependency
		public static Action<string> CertificateErrorHandler = err => { };
	}
}
