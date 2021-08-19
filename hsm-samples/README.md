# Fabric Gateway HSM Samples

The samples in this repo show how to create client applications that invoke transactions with HSM Identities using the
new embedded Gateway in Fabric.

The samples will only run against Fabric v2.4 and higher.  The easiest way of setting up a gateway
enabled Fabric network is to use the scenario test framework that is part of this `fabric-gateway` repository using the
following command:

```
export PEER_IMAGE_PULL=hyperledger/fabric-peer:2.4.0-beta
make sample-network
```

This will create a local docker network comprising five peers across three organisations and a single ordering node.

Sample client applications are available to demonstrate the features of the Fabric Gateway and associated SDKs using this network.
More details of the samples can be found on the [samples page](https://github.com/hyperledger/fabric-gateway/tree/main/samples).

## C Compilers

In order for the client application to run successfully you must ensure you have C compilers and Python 3 (Note that Python 2 may still work however Python 2 is out of support and could stop working in the future) installed otherwise the node dependency `pkcs11js` will not be built and the application will fail. The failure will have an error such as

```
Error: Cannot find module 'pkcs11js'
```

how to install the required C Compilers and Python will depend on your operating system and version.

## Install SoftHSM

In order to run the application in the absence of a real HSM, a software
emulator of the PKCS#11 interface is required.
For more information please refer to [SoftHSM](https://www.opendnssec.org/softhsm/).

SoftHSM can either be installed using the package manager for your host system:

* Ubuntu: `sudo apt install softhsm2`
* macOS: `brew install softhsm`
* Windows: **unsupported**

Or compiled and installed from source:

1. install openssl 1.0.0+ or botan 1.10.0+
2. download the source code from <https://dist.opendnssec.org/source/softhsm-2.5.0.tar.gz>
3. `tar -xvf softhsm-2.5.0.tar.gz`
4. `cd softhsm-2.5.0`
5. `./configure --disable-gost` (would require additional libraries, turn it off unless you need 'gost' algorithm support for the Russian market)
6. `make`
7. `sudo make install`

## Initialize a token to store keys in SoftHSM

If you have not initialized a token previously (or it has been deleted) then you will need to perform this one time operation

```bash
echo directories.tokendir = /tmp > $HOME/softhsm2.conf
export SOFTHSM2_CONF=$HOME/softhsm2.conf
softhsm2-util --init-token --slot 0 --label "ForFabric" --pin 98765432 --so-pin 1234
```

This will create a SoftHSM configuration file called `softhsm2.conf` and will be stored in your home directory. This is
where the sample expects to find a SoftHSM configuration file

The Security Officer PIN, specified with the `--so-pin` flag, can be used to re-initialize the token,
and the user PIN (see below), specified with the `--pin` flag, is used by applications to access the token for
generating and retrieving keys.

## Install PKCS#11 enabled fabric-ca-client binary
To be able to register and enroll identities using an HSM you need a PKCS#11 enabled version of `fabric-ca-client`
To install this use the following command

```bash
go get -tags 'pkcs11' github.com/hyperledger/fabric-ca/cmd/fabric-ca-client
```
## Enroll the HSM User

A user, `HSMUser`, who is HSM managed needs to be registered then enrolled for the sample

```bash
make enroll-hsm-user
```

This will register a user `HSMUser` with the CA in Org1 (if not already registered) and then enroll that user which will
generate a certificate on the file system for use by the sample. The private key is stored in SoftHSM

### Go SDK

For HSM support you need to ensure you include the `pkcs11` build tag.

```
cd <base-path>/fabric-gateway/hsm-samples/go
go run -tags pkcs11 hsm-sample.go
```

### Node SDK

```
cd <base-path>/fabric-gateway/hsm-samples/node
npm install
npm run build
npm start
```

### Java SDK

Java does HSM differently to Go and Node. For Java you need a PKCS11 security provider and each one will potentially work slighly different
to the others.

The instructions here are specific to getting SoftHSM working with the Sun PKCS11 Security provider, different PKCS11 providers and maybe
even different HSMs may require a different procedure

#### Getting an identity into SoftHSM

Unfortunately you can't use the fabric-ca-client binary or the SDKs to perform this. The Sun PKCS11 Security provider requires identities to be stored in a manner it expects otherwise it will ignore them or will not return a PrivateKey object representative of Elliptic Curve
required for signing.

#### Configure Sub PKCS11 Security provider to use SoftHSM

1. Create options file with the following contents (assuming that the softhsm library is located in `/usr/lib/softhsm/libsofthsm2.so`)

```
library=/usr/lib/softhsm/libsofthsm2.so
name=softhsm2
slotListIndex=0
attributes(*,CKO_PRIVATE_KEY,*) = {
  CKA_SENSITIVE = false
  CKA_EXTRACTABLE = true
}
```

`slotListIndex` assumes you have followed this README and you have created a single slot. The `attributes` section insures that keys and certificates imported into the HSM can be correctly retrieved as Elliptic Curve private keys rather than just generic private keys.

store this file somewhere appropriate, for the purposes of this sample assume it's /var/pkcs11.cfg

2. configure jre security provider
locate `java.security` file in your Java JRE/SDK installation, eg $JAVA_HOME/conf/Security
edit the file and locate the SunPKCS11 entry, eg

```
security.provider.12=SunPKCS11
```

and update it to point to the options file you have created, eg

```
security.provider.12=SunPKCS11 /var/pkcs11.cfg
```

#### Convert and import an existing identity into the HSM

 1. cp fabric-gateway/scenario/fixtures/crypto-material/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem hsmuser.pem
 2. cp fabric-gateway/scenario/fixtures/crypto-material/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/key.pem
 3. openssl pkcs12 -export -in hsmuser.pem -inkey key.pem -out hsmuser.p12 (set password for .p12 keystore)
 4. keytool -importkeystore -deststorepass 98765432 -destkeystore NONE -deststoretype PKCS11 -srckeystore hsmuser.p12 -srcstoretype PKCS12 (use .p12 keystore password)
 5. keytool -changealias -keystore NONE -storetype PKCS11 -alias "1" -destalias "HSMUser" (use HSM pin)

#### Convert Java Sample to use Private Key from HSM rather than from file system

In the original sample, the private key is obtained from the private key file. Here the difference is the private key is now obtained from a Java keystore which is backed by the PKCS11 provider

create the following methods in the sample
```java
    private static Signer newHSMSigner(KeyStore ks, String alias) throws IOException, InvalidKeyException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
    	final PrivateKey pk = (PrivateKey)ks.getKey(alias, null);
    	if (pk == null) {
    		throw new IOException("No private key found");  // TODO: Need to fix
    	}

        return Signers.newPrivateKeySigner(pk);

    }

    private static KeyStore getKeyStore() throws KeyStoreException {
        KeyStore ks = KeyStore.getInstance("PKCS11");
        try {
            ks.load(null, "98765432".toCharArray()); // It's the Pin
        } catch(Exception e) {  // TODO: Need to fix
            e.printStackTrace();
        }
        return ks;
    }
```

In the main method, change the creation of the `Gateway.Builder` to use the HSMSigner

```java
        Gateway.Builder builder = Gateway.newInstance()
                .identity(newIdentity())
                .signer(newHSMSigner(getKeyStore(), "HSMUser"))  // <--- change this line
                .connection(channel);
```

## Cleanup

When you are finished running the samples, the local docker network can be brought down with the following command:

`docker rm -f $(docker ps -aq) && docker network prune --force`