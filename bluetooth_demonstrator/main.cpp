#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <winsock2.h>
#include <ws2bth.h>
#include <BluetoothAPIs.h>
#include <atlstr.h>

struct bt_device_info
{
    explicit bt_device_info(const BLUETOOTH_DEVICE_INFO_STRUCT& i) : info(i) {}

    BLUETOOTH_DEVICE_INFO_STRUCT info;
};

std::vector<bt_device_info> scan_bt_devices_via_bluetoothapis()
{
    BLUETOOTH_DEVICE_SEARCH_PARAMS search_params =
    {
        sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS), // dwSize (size)
        FALSE, // fReturnAuthenticated (return authenticated devices)
        FALSE, // fReturnRemembered (return remembered devices)
        TRUE, // fReturnUnknown (return unknown devices)
        TRUE, // fReturnConnected (return connected devices)
        TRUE, // fIssueInquiry (issue new inquiry)
        3, // cTimeoutMultiplier (number of increments of 1.28 sec, maximum value is 48)
        NULL // 
    };

    BLUETOOTH_DEVICE_INFO_STRUCT device_info;
    device_info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO_STRUCT);

    auto devices = std::vector<bt_device_info>{};
    auto find_handle =  BluetoothFindFirstDevice(&search_params, &device_info);

    if (find_handle)
    {
        do
        {
            devices.emplace_back(device_info);
        } while (BluetoothFindNextDevice(find_handle, &device_info));
    }

    if (!BluetoothFindDeviceClose(find_handle))
    {
        throw std::exception{ "BluetoothFindDeviceClose() failed" };
    }

    return devices;
}

int main()
{
    try
    {
        const auto bt_devices = scan_bt_devices_via_bluetoothapis();
        std::for_each(bt_devices.cbegin(), bt_devices.cend(), [](const bt_device_info& device) 
        {
            std::cout << "\n" <<
                "Device name:    " << CW2A(device.info.szName) << "\n" <<
                "Device address: " << std::hex << std::showbase << device.info.Address.ullLong << "\n" <<
                "Device class:   " << std::dec << device.info.ulClassofDevice << std::endl;
        });
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << "\n" <<
            "Error code: " << WSAGetLastError() <<
            std::endl;
    }

    return 0;
}
