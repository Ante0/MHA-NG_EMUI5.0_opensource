LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_WHOLE_STATIC_LIBRARIES := libavutil libavformat libavcodec libswscale libswresample
#LOCAL_SHARED_LIBRARIES := libavformat
LOCAL_SHARED_LIBRARIES := liblog libcutils
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := lib_k3_ffmpeg
ARCH := arm
LOCAL_PRELINK_MODULE := false
include $(BUILD_SHARED_LIBRARY)
include $(call all-makefiles-under,$(LOCAL_PATH))
