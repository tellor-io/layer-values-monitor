These contracts can be used to test the saga guard flag. 

1. Deploy a contract with desired queryId
2. Make yourself a guardian
3. Adjust config.toml contract address for desired queryId
4. Make sure saga variables are filled out in env file
5. On your test network (local is easiest), create a reporter and report a bad price for desired query Id
6. LVM should auto dispute the report and pause the contract