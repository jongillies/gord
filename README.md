# gord

Forked from http://code.google.com/p/gord/ 

# Status

GORD code is open sourced and available for mass consumption. Code tests are not yet released, though we plan to release them soon. We assure you GORD has extensive testing with > 95% test coverage in unit and integration tests. Please check back soon!

For GORD discussion, please join gord-discuss@googlegroups.com.

# Objective

Provide a server, offering an open API to interact with Microsoft® System Center Configuration Manager® (SCCM), formerly known as Microsoft® System Management Server® (SMS). The GORD server needs to run on a single SCCM Data Provider server in an organization’s SCCM infrastructure.

# Background

SCCM provides a rich environment to remotely manage an installed base of Windows® machines. Connectivity to the SCCM interface is available via the Windows® Management Instrumentation (WMI) protocol, or by connecting directly to Microsoft® SQL Server® via its native MSSQL protocol. WMI is only accessible from an OS with a DCOM stack, which is currently only reliable on Windows®. Therefore direct SCCM connectivity from any other operating system is currently unsupported.

Unix operating systems can access Microsoft® SQL Server® through libraries like Python's pymssql, which relies upon libfreetds. Unfortunately, the pymssql module quality has been inconsistent in the past. In addition, the learning curve for SCCM’s often undocumented SQL interface can be steep. Furthermore, certain critical management functionality is accessible via WMI, but not the SQL-only interface.

# Overview

GORD provides a central resource to access SCCM functionality via an API abstracted from SCCM. It is written in Python and is accessible over open platform-agnostic protocols: currently XML-RPC and REST+JSON over HTTP or HTTPS.

The server process itself is designed to operate as a Windows® service, in the manner that Windows® system administrators are familiar with. In other words, it can be managed via the standard Microsoft® Service Controller or via the Services MMC snap-in, it writes logs into Event Viewer. 

![gord-workflow.png](https://raw.github.com/jongillies/gord/master/doc/gord-service-design.png)

The client communicates with GORD over HTTP (or HTTPS). GORD handles authentication, and adapts calls onto the underlying API. In this example, GORD is speaking via the WMI protocol to the SCCM Data Provider, so HTTP and WMI are the well defined boundaries that separate the client from the underlying system. GORD is intentionally designed such that it is straightforward to replace either interface; a transport besides HTTP can be added, and/or an underlying system other than WMI/SCCM can be exposed.

The below chart depicts how the modular pieces of GORD fit together. The Windows® Service manages execution of the HTTP(S) server. Requests through the HTTP server are matched with registered methods in service.ServiceMethods, and once authenticated execute code for direct interaction with the underlying API. 

gord-service-design.png

# SCCM Functionality Made Available

GORD provides access to the following types of SCCM functionality:

* Get host information
* Get collection information
* Modify collection membership
* Refresh policies on host
* Get applications installed on host 

# Specific Method Reference

See: WmiutilPydoc

# Design

The service module includes classes to run HTTP RPC servers. These servers are generic Python-based servers (inheriting from SocketServer, etc.) and are not Windows®-specific.

The service module uses the auth module for authentication. Various auth classes are supplied that can authenticate against LDAP or Windows® APIs. The auth class also describes the type of credentials it needs and how they should be obtained. For example, an auth method may require one token string, which is supplied as the first argument to a method being called. Alternately, it could require multiple arguments, or request HTTP basic auth for a username-password pair.

The winservice module contains code to run Windows® Services, which start RPC servers from the service module. The winservice module is a Windows®-specific feature.

# Authentication Modules

The code that dispatches methods requested via HTTP to the methods themselves also supports the concept of an authentication class. The base classes and a few examples are in the auth module.

Each authentication class offers a basic interface:

    Static Variables
        REQUIRED_PARAM_COUNT: (int) How many items of authentication detail are required to perform an authentication check. Example: 2, for a username and password.
        USER_AUTH: (bool) Whether the authentication class needs authentication to be requested on its behalf, before the method is called. This is currently implemented by having the HTTP server require basic auth on the request. 
    Methods
        Auth(method_name, parameters)
            Arguments
                method_name: (string) Name of the method to be called..
                parameters: A list of authentication details provided by the caller. 
            Returns
                True: If authentication passes.
                False: If authentication does not pass, but the authentication process did complete without errors. 
            Raises
                common.AuthenticationError: If an error occurs while the authentication process is being performed. If an error is raised authentication has also failed. There are no partial success conditions. 

# Configuration and Installation

## Configuration

The configuration of GORD is contained in the common.py module.

    Class: Network
        SERVICE_HOST: (string) Host that the server is running on, e.g. the local hostname.
        SERVICE_PORT: (int) Port to run on.
        AUTH_CLASS: (string) Name of the authentication class from auth module to use. Use AuthNone for a generic placeholder class which performs no authentication.
        USE_HTTPS: (bool) Value instructing server to use https (True) or http (False).
        PEM_FILENAME: (string) Value pointing to the PEM file for the https server, required only when USE_HTTPS is True, otherwise should be None. 
    Class: AuthConfig
        NO_AUTH_METHODS: (list of strings) Method names that can be called without authentication. 

## Installation and Use

On the SCCM Data Provider Windows Server:

    Install ActivePython 2.4.
        GORD may run on other versions of Python, but itâs only tested with ActivePython 2.4. 
    Install Tim Golden's WMI module.
    Choose an installation path (the default is C:\GORD).
        If not using default installation path, edit INSTALL_PATH in gord.py. 
    Configure settings in the Network and AuthConfig classes described above, if necessary.
    Open a command prompt (i.e. Start -> Run, type cmd and hit Enter).
    Run install.bat.
        On success you will see, "Installing service GORD. Service installed." 
    Run run.bat debug.
        On success you will see, "Debugging service GORD. The GORD service has started" 
    Finally, to start the service, run sc start gord.  
