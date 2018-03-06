Title: Python pip update issues
Date: 2018-03-06 10:42:00.093415
Modified: 2018-03-06 10:42:00.093415
Category: python
Tags: python
Slug: python-pip-update-issues
Authors: Alset0326
Summary: python pip issues in ubuntu

- libxml/xmlversion.h: No such file or directory
	
    ```
    sudo apt install libxml2-dev libxslt1-dev
    ```
	
- EnvironmentError: mysql_config not found

    ```
    sudo apt install libmysqlclient-dev
    ```

- numpy.distutils.system_info.NotFoundError: no lapack/blas resources found

    ```
    sudo apt install liblapack-dev libblas-dev texinfo libicu-dev 
    ```

- `__main__.ConfigurationError`: Could not run curl-config: [Errno 2] No such file or directory

    ```
    sudo apt install libcurl4-openssl-dev
    ```

- fatal error: sqlfront.h: No such file or directory

    ```
    sudo apt install freetds-dev 
    ```

-  library dfftpack has Fortran sources but no Fortran compiler found

    ```
    sudo apt install gfortran
    ```

-  fatal error: cups/cups.h: No such file or directory

    ```
    sudo apt install libcups2-dev
    ```

-  fatal error: openssl/aes.h: No such file or directory

    ```
    sudo apt install libssl-dev
    ```

- fatal error: libsmbclient.h: No such file or directory

    ```
    sudo apt install libsmbclient-dev
    ```

-  fatal error: sqlite3.h: No such file or directory

    ```
    sudo apt install libsqlite3-dev
    ```

-  fatal error: pcap.h: No such file or directory

    ```
    sudo apt install libpcap-dev
    ```

-  Error: Unable to find 'openssl/opensslconf.h'

    ```
    cd /usr/include/openssl/
    ln -s ../x86_64-linux-gnu/openssl/opensslconf.h .
    ```

-  fatal error: 'unicode/utypes.h': No such file or directory

    ```
    sudo apt install libicu-dev
    ```

- No package 'cairo' found

    ```
    sudo apt install libcairo2-dev
    ```

- gnutls/gnutls.h: No such file or directory

    ```
    sudo apt install libghc-gnutls-dev
    ```

- No package 'gobject-introspection-1.0' found

    ```
    sudo apt install libgirepository1.0-dev
    ```

