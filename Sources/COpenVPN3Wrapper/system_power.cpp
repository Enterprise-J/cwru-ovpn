#include "cwru_openvpn3_wrapper.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <memory>
#include <new>

struct cwru_power_observer {
    io_connect_t connection{};
    IONotificationPortRef port{};
    io_object_t notifier{};
    cwru_power_callback_t callback{};
    void *context{};
};

static void power_changed(void *context, io_service_t, natural_t message, void *argument)
{
    auto &observer = *static_cast<cwru_power_observer *>(context);
    if (message == kIOMessageSystemWillSleep || message == kIOMessageCanSystemSleep)
    {
        if (message == kIOMessageSystemWillSleep)
            observer.callback(observer.context, false);
        IOAllowPowerChange(observer.connection, reinterpret_cast<intptr_t>(argument));
    }
    else if (message == kIOMessageSystemHasPoweredOn)
        observer.callback(observer.context, true);
}

cwru_power_observer_t *cwru_power_observe(cwru_power_callback_t callback, void *context)
{
    if (!callback)
        return nullptr;
    std::unique_ptr<cwru_power_observer> observer(new (std::nothrow) cwru_power_observer{});
    if (!observer)
        return nullptr;
    observer->callback = callback;
    observer->context = context;
    observer->connection = IORegisterForSystemPower(observer.get(), &observer->port, power_changed, &observer->notifier);
    if (!observer->connection)
        return nullptr;
    CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(observer->port), kCFRunLoopCommonModes);
    return observer.release();
}

void cwru_power_stop(cwru_power_observer_t *observer)
{
    if (!observer)
        return;
    CFRunLoopRemoveSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(observer->port), kCFRunLoopCommonModes);
    IODeregisterForSystemPower(&observer->notifier);
    IOServiceClose(observer->connection);
    IONotificationPortDestroy(observer->port);
    delete observer;
}
