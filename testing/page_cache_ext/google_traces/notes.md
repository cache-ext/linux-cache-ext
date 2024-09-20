# Google IO Traces

GitHub: https://github.com/google-research-datasets/thesios
Stored at: https://console.cloud.google.com/storage/browser/thesios-io-traces

## Description

The data includes I/O traces from 2024/01/15 to 2024/03/15 from three different clusters (with different types of traffic). A one-day trace is stored as sharded CSV files, named {cluster}_{disk_size}/{yyyymmdd}/data*. Each trace contains I/O requests to a storage server with a single disk (HDD) attached.

