#include <algorithm>
#include <iostream>
#include <string>
#include <map>

#include <winsock2.h>
#include <ws2bth.h>
#include <BluetoothAPIs.h>
#include <atlstr.h>

struct bt_device_info
{
    explicit bt_device_info(const BLUETOOTH_DEVICE_INFO_STRUCT& i) : info(i) {}

    BLUETOOTH_DEVICE_INFO_STRUCT info;
};

std::map<std::size_t, bt_device_info> scan_bt_devices()
{
    BLUETOOTH_DEVICE_SEARCH_PARAMS search_params =
    {
        sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS), // dwSize (size)
        TRUE, // fReturnAuthenticated (return authenticated devices)
        TRUE, // fReturnRemembered (return remembered devices)
        TRUE, // fReturnUnknown (return unknown devices)
        TRUE, // fReturnConnected (return connected devices)
        TRUE, // fIssueInquiry (issue new inquiry)
        4, // cTimeoutMultiplier (number of increments of 1.28 sec, maximum value is 48)
        NULL // 
    };

    BLUETOOTH_DEVICE_INFO_STRUCT device_info;
    device_info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO_STRUCT);

    auto devices = std::map<std::size_t, bt_device_info>{};
    auto find_handle =  BluetoothFindFirstDevice(&search_params, &device_info);
    int count = 0;

    if (find_handle)
    {
        do
        {
            devices.emplace(++count, device_info);
        } while (BluetoothFindNextDevice(find_handle, &device_info));
    }

    if (!BluetoothFindDeviceClose(find_handle))
    {
        throw std::exception{ "BluetoothFindDeviceClose() failed" };
    }

    return devices;
}

// Authentication callback
BOOL WINAPI BluetoothAuthCallback(LPVOID param, PBLUETOOTH_AUTHENTICATION_CALLBACK_PARAMS auth_callback_params)
{
    DWORD result = ERROR_SUCCESS;

    fprintf(stderr, "BluetoothAuthCallback 0x%xn", static_cast<unsigned int>(auth_callback_params->deviceInfo.Address.ullLong));
    BLUETOOTH_AUTHENTICATE_RESPONSE auth_response;
    auth_response.authMethod = auth_callback_params->authenticationMethod;
    fprintf(stderr, "Authmethod %dn", auth_response.authMethod);
    fprintf(stderr, "I/O : %dn", auth_callback_params->ioCapability);

    // With BLUETOOTH_AUTHENTICATION_METHOD_NUMERIC_COMPARISON connection working
    if (auth_response.authMethod == BLUETOOTH_AUTHENTICATION_METHOD_NUMERIC_COMPARISON)
    {
        fprintf(stderr, "Numeric Comparison supportedn");

        auth_response.bthAddressRemote = auth_callback_params->deviceInfo.Address;
        auth_response.negativeResponse = FALSE;

        // Respond with numerical value for Just Works pairing
        auth_response.numericCompInfo.NumericValue = 1;

        // Send authentication response to authenticate device
        result = BluetoothSendAuthenticationResponseEx(NULL, &auth_response);
    }
    // With BLUETOOTH_AUTHENTICATION_METHOD_LEGACY connection not working
    else if (auth_response.authMethod == BLUETOOTH_AUTHENTICATION_METHOD_LEGACY)
    {
        auth_response.bthAddressRemote = auth_callback_params->deviceInfo.Address;
        auth_response.negativeResponse = FALSE;

        //Pin
        UCHAR pin[] = "0000";
        std::copy(pin, pin + sizeof(pin), auth_response.pinInfo.pin);
        auth_response.pinInfo.pinLength = sizeof(pin) - 1;;

        // Respond with numerical value for Just Works pairing
        //AuthRes.numericCompInfo.NumericValue = 1;

        fprintf(stderr, "Authentication via a PINn");
        result = BluetoothSendAuthenticationResponseEx(NULL, &auth_response);
    }

    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "BluetoothSendAuthenticationResponseEx ret %dn", result);
    }
    else
    {
        fprintf(stderr, "BluetoothAuthCallback finish");
    }

    return 1; // This value is ignored
}

void pair(bt_device_info device_info)
{
    auto device = device_info.info;

    std::wstring ws = device.szName;
    std::cout << "Pairing device " << std::string(ws.begin(), ws.end()) << std::endl;

    // register callback
    std::cout << "Registering callback" << std::endl;
    HBLUETOOTH_AUTHENTICATION_REGISTRATION callback_handle = 0;
    auto result = BluetoothRegisterForAuthenticationEx(NULL, &callback_handle, (PFN_AUTHENTICATION_CALLBACK_EX)&BluetoothAuthCallback, NULL);

    if (result != ERROR_SUCCESS)
    {
        return;
    }

    // authenticate
    result = BluetoothAuthenticateDeviceEx(NULL, NULL, &device, NULL, MITMProtectionNotRequired);

    switch (result)
    {
    case ERROR_SUCCESS:
        std::cout << "pair device success" << std::endl;
        break;

    case ERROR_CANCELLED:
        std::cout << "pair device failed, user cancelled" << std::endl;
        break;

    case ERROR_INVALID_PARAMETER:
        std::cout << "pair device failed, invalid parameter" << std::endl;
        break;

    case ERROR_NO_MORE_ITEMS:
        std::cout << "pair device failed, device appears paired already" << std::endl;
        break;

    default:
        std::cout << "pair device failed, unknown error, code " << (unsigned int)result << std::endl;
        break;
    }
}

int main()
{
    try
    {
        const auto bt_devices = scan_bt_devices();
        std::for_each(bt_devices.cbegin(), bt_devices.cend(), [](const auto& map_elem) 
        {
            std::cout << "\n" << "[" << map_elem.first << "]\n" <<
                "Device name:    " << CW2A(map_elem.second.info.szName) << "\n" <<
                "Device address: " << std::hex << std::showbase << map_elem.second.info.Address.ullLong << "\n" <<
                "Device class:   " << std::dec << map_elem.second.info.ulClassofDevice << std::endl;
        });

        std::cout << "\nEnter number of device to pair with: ";
        std::string number;
        std::getline(std::cin, number);

        pair(bt_devices.at(std::stoul(number)));
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << "\n" <<
            "Error code: " << WSAGetLastError() <<
            std::endl;
    }

    return 0;
}
