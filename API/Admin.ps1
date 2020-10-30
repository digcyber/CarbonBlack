# Start by applying the global variables found in global.ps1

#==================
# Simple admin code

## How to get specific sensor ID details
Invoke-RestMethod -Method GET -Headers @{'X-Auth-Token' = $MyAPIToken} -URI $BaseURL'/v1/sensor/1'

## How to set new group_id for a specific sensor ID
#Set the body variable (change #3 for the group ID you want to change it to)
$gid = '{ "group_id": "3" }'

Invoke-RestMethod -Method PUT -Headers @{'X-Auth-Token' = $MyAPIToken} -URI $BaseURL'/v1/sensor/1' -Body $gid


## Get your user details
# Set variabl with your username
$uname = 'testuser'
Invoke-RestMethod -Method GET -Headers @{'X-Auth-Token' = $MyAPIToken} -URI $BaseURL'/user/'$uname

## Reset API key for your own user

# set variable with your username
$uname = 'testuser'
Invoke-RestMethod -Method POST -Headers @{'X-Auth-Token' = $MyAPIToken} -URI $BaseURL'/v1/user/'$uname'/token' -Body '{reset_api_token: true}'
