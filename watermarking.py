import cv2
from imwatermark import WatermarkEncoder, WatermarkDecoder

def startwatermark(bg,wm):
    bgr = cv2.imread(bg)

    encoder = WatermarkEncoder()
    encoder.set_watermark('bytes', wm.encode("utf-8"))
    print( wm.encode("utf-8"))
    bgr_encoded = encoder.encode(bgr, 'dwtDctSvd')
    #
    cv2.imwrite(bg, bgr_encoded)
    # cv2.imwrite(bgg, bgr_encoded)
def decodewatermark(bg, length):
    bgr = cv2.imread(bg)

    decoder = WatermarkDecoder('bytes', length)
    watermark = decoder.decode(bgr, 'dwtDctSvd')
    try:
        return (watermark.decode("utf-8"),"THE WATER MARK FOR TESTING")
    except Exception as e:
        print("Watermark not found, Invalid!")

# wm = "SHIBA"
# # startwatermark("./static/images/shibatest.jpg",wm,"./static/images/editedshibatest.jpg")
# print(decodewatermark("./static/images/editedshibatest.jpg", len(wm)*8))
