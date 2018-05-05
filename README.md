# Configure-IMIntegration

Configures IM Integration on Exchange 2013 servers with the Mailbox server role
that have a valid certificate assigned for IIS services, and optionally can configure
all CAS servers.

## Prerequisites

Script requires Microsoft Exchange Management Shell.
	
## Usage

```
Configure-IMIntegration.ps1 -PoolFQDN lync.contoso.com -AllMaibox -AllCAS
```
This configures IM integration on all Mailbox servers and CAS servers for lync.contoso.com

```
Configure-IMIntegration.ps1 -Server mbx1.contoso.com -PoolFQDN lync.contoso.com
```
This configures IM integration on the specified server for lync.contoso.com

## Contributing

N/A

## Versioning

Initial version published on GitHub is 1.0. Changelog is contained in the script.

## Authors

* Michel de Rooij [initial work] https://github.com/michelderooij

## License

This project is licensed under the MIT License - see the LICENSE.md for details.

## Acknowledgments

N/A
 