#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <winsock2.h>
#include <ws2bth.h>
#include <BluetoothAPIs.h>
#include <atlstr.h>

using BT_ADDR = unsigned long long;

struct bt_device_info
{
    std::uint16_t get_nap()
    {
        return GET_NAP(bt_address);
    }

    std::uint32_t get_sap()
    {
        return GET_SAP(bt_address);
    }

    std::uint64_t bt_address{ 0 };
    std::string bt_device_name;
    std::uint32_t bt_namespace{ 0 };
    std::uint32_t bt_device_class{ 0 };
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
            auto info = bt_device_info{};
            info.bt_device_name = CW2A(device_info.szName);
            info.bt_address = device_info.Address.ullLong;
            info.bt_device_class = device_info.ulClassofDevice;

            devices.emplace_back(info);
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
        std::for_each(bt_devices.cbegin(), bt_devices.cend(), [](const auto& device_info) 
        {
            std::cout << "\n" <<
                "Device name:    " << device_info.bt_device_name << "\n" <<
                "Device address: " << std::hex << std::showbase << device_info.bt_address << "\n" <<
                "Device class:   " << std::dec << device_info.bt_device_class << std::endl;
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
