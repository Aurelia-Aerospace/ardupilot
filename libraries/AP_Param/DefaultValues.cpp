#include "DefaultValues.h"

DefaultValues *DefaultValues::_singleton = nullptr;

DefaultValues::DefaultValues()
{
    if (_singleton) {
        AP_HAL::panic("Too many DefaultValues instances");
    }
    _singleton = this;
}

namespace AP
{
    DefaultValues *dv()
    {
        return DefaultValues::get_singleton();
    }
}
