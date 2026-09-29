#pragma once

#include <AP_Common/AP_Common.h>
#include <AP_Param/AP_Param.h>

class DefaultValues
{
public:
    DefaultValues();
    CLASS_NO_COPY(DefaultValues);
    static DefaultValues *get_singleton() { return _singleton; }

private:
    static DefaultValues *_singleton;
};

namespace AP
{
    DefaultValues *dv();
}
