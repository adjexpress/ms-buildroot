/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "loop_control.h"

#include <fcntl.h>
#include <iostream>
#include <linux/loop.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

// #include "android-base/logging.h"
#include "stringprintf.h"
#include "unique_fd.h"

#include "utility.h"

namespace android {
namespace dm {

LoopControl::LoopControl() : control_fd_(-1) {
    control_fd_.reset(TEMP_FAILURE_RETRY(open(kLoopControlDevice, O_RDWR | O_CLOEXEC)));
    if (control_fd_ < 0) {
        std::cout<< "ERROR" << "Failed to open loop-control";
    }
}

bool LoopControl::Attach(int file_fd, const std::chrono::milliseconds& timeout_ms,
                         std::string* loopdev) const {
    auto start_time = std::chrono::steady_clock::now();
    auto condition = [&]() -> WaitResult {
        if (!FindFreeLoopDevice(loopdev)) {
            std::cout<< "ERROR" << "Failed to attach, no free loop devices";
            return WaitResult::Fail;
        }

        auto now = std::chrono::steady_clock::now();
        auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        if (!WaitForFile(*loopdev, timeout_ms - time_elapsed)) {
            std::cout<< "ERROR" << "Timed out waiting for path: " << *loopdev;
            return WaitResult::Fail;
        }

        android::base::unique_fd loop_fd(
                TEMP_FAILURE_RETRY(open(loopdev->c_str(), O_RDWR | O_CLOEXEC)));
        if (loop_fd < 0) {
            std::cout<< "ERROR" << "Failed to open: " << *loopdev;
            return WaitResult::Fail;
        }

        if (int rc = ioctl(loop_fd, LOOP_SET_FD, file_fd); rc == 0) {
            return WaitResult::Done;
        }
        if (errno != EBUSY) {
            std::cout<< "ERROR" << "Failed LOOP_SET_FD";
            return WaitResult::Fail;
        }
        return WaitResult::Wait;
    };
    if (!WaitForCondition(condition, timeout_ms)) {
        std::cout<< "ERROR" << "Timed out trying to acquire a loop device";
        return false;
    }
    return true;
}

bool LoopControl::Detach(const std::string& loopdev) const {
    if (loopdev.empty()) {
        std::cout<< "ERROR" << "Must provide a loop device";
        return false;
    }

    android::base::unique_fd loop_fd(TEMP_FAILURE_RETRY(open(loopdev.c_str(), O_RDWR | O_CLOEXEC)));
    if (loop_fd < 0) {
        std::cout<< "ERROR" << "Failed to open: " << loopdev;
        return false;
    }

    int rc = ioctl(loop_fd, LOOP_CLR_FD, 0);
    if (rc) {
        std::cout<< "ERROR" << "Failed LOOP_CLR_FD for '" << loopdev << "'";
        return false;
    }
    return true;
}

bool LoopControl::FindFreeLoopDevice(std::string* loopdev) const {
    int rc = ioctl(control_fd_, LOOP_CTL_GET_FREE);
    if (rc < 0) {
        std::cout<< "ERROR" << "Failed to get free loop device";
        return false;
    }

    // Ueventd on android creates all loop devices as /dev/block/loopX
    // The total number of available devices is determined by 'loop.max_part'
    // kernel command line argument.
    *loopdev = ::android::base::StringPrintf("/dev/block/loop%d", rc);
    return true;
}

bool LoopControl::EnableDirectIo(int fd) {
#if !defined(LOOP_SET_BLOCK_SIZE)
    static constexpr int LOOP_SET_BLOCK_SIZE = 0x4C09;
#endif
#if !defined(LOOP_SET_DIRECT_IO)
    static constexpr int LOOP_SET_DIRECT_IO = 0x4C08;
#endif

    // Note: the block size has to be >= the logical block size of the underlying
    // block device, *not* the filesystem block size.
    if (ioctl(fd, LOOP_SET_BLOCK_SIZE, 4096)) {
        std::cout<< "ERROR" << "Could not set loop device block size";
        return false;
    }
    if (ioctl(fd, LOOP_SET_DIRECT_IO, 1)) {
        std::cout<< "ERROR" << "Could not set loop direct IO";
        return false;
    }
    return true;
}

LoopDevice::LoopDevice(android::base::borrowed_fd fd, const std::chrono::milliseconds& timeout_ms,
                       bool auto_close)
    : fd_(fd), owned_fd_(-1) {
    if (auto_close) {
        owned_fd_.reset(fd.get());
    }
    Init(timeout_ms);
}

LoopDevice::LoopDevice(const std::string& path, const std::chrono::milliseconds& timeout_ms)
    : fd_(-1), owned_fd_(-1) {
    owned_fd_.reset(open(path.c_str(), O_RDWR | O_CLOEXEC));
    if (owned_fd_ == -1) {
        std::cout<< "ERROR" << "open failed for " << path;
        return;
    }
    fd_ = owned_fd_;
    Init(timeout_ms);
}

LoopDevice::~LoopDevice() {
    if (valid()) {
        control_.Detach(device_);
    }
}

void LoopDevice::Init(const std::chrono::milliseconds& timeout_ms) {
    valid_ = control_.Attach(fd_.get(), timeout_ms, &device_);
}

}  // namespace dm
}  // namespace android
