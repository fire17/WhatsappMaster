try:
    import Image
except ImportError:
    import PIL
    from PIL import Image
# ASCII_CHARS = ["@", "#", "S", "%", "?", "*", "+", ";", ":", ",", "."]
# ASCII_CHARS = ["Q", "O", "W", "S", "E", "T", "F", "w", "-", "_", " "]
ASCII_CHARS = ["🟠", "🟡", "🟢", "🔵", "🟣", "⚫", "⚪", "🟡", "🔴", "🔘", " "]
ASCII_CHARS = ["⚪", "🟡", "🟠", "🟢", "🔵", "🟣", "🟣", "🟤", "🔘", "⚫", "⚫"][::-1]
ASCII_CHARS = ["⚪", "🟡", "🟠", "🟢", "🔵", "🟣", "🟣", "🟤", "🔘", "⚫", "⚫"]
ASCII_CHARSv = [(255,255,255), (255,255,0), (255,128,0), (0,255,0), (0,0,255), (255,0,255), (255,0,255), (100,50,0),(100,0,100),(20,0,0),(0,0,0),]
# #
# from AsciService import *
# ITA("test/thumnail.jpg",30)
# ITA("test/pp.jpeg",30)
# ITA("test/pp2.jpeg",30)

a = ''

class ImageToAscii:
    def __init__(self,imagePath: str=None,width:int=100,outputFile:str=None):
        '''
        path - The path/name of the image ex: <image_name.png>\n
        width - The width you want the Ascii art to have\n
        outputfile - If you want to store the Ascii art in a txt file then set it to <file_name.txt> else keep it None
        '''
        self.path = imagePath
        self.width = width
        try:
            self.image = PIL.Image.open(self.path)
            width, height = self.image.size
            totalPixels = width * height
        except:
            if imagePath is None:
                print("Invalid path name")
            elif self.width is None:
                print("Invalid Width provided")
        self.new_image_data = self.pixelsToAscii(self.resizeImage(self.image))
        # self.new_image_data = self.pixelsToAscii(self.converToGrayscale(self.resizeImage(self.image)))

        self.pixel_count = len(self.new_image_data)

        # self.ascii_image = ("\n".join([self.new_image_data[index:(index+self.width)] for index in range(0, self.pixel_count, self.width)])).rstrip().replace(" ","⠀")
        self.ascii_image = [self.new_image_data[index:(index+self.width)] for index in range(0, self.pixel_count, self.width)]
        minStart = 100
        minEnd = 100
        for k in range(len(self.ascii_image)):
            minStart = min(minStart,len(self.ascii_image[k])- len(self.ascii_image[k].lstrip()))
        for k in range(len(self.ascii_image)):
            minEnd = min(minEnd,len(self.ascii_image[k])- len(self.ascii_image[k].rstrip()))
            # self.ascii_image[k] = self.ascii_image[k].rstrip().replace(" ","⠀")
        print("!!!!!!!!!!!!!minStart:{0}".format(minStart))
        print("!!!!!!!!!!!!!minStart:{0}".format(minEnd))
        minStart    = max(0,minStart-1)
        minEnd      = max(1,minEnd-1)
        for k in range(len(self.ascii_image)):
            # self.ascii_image[k] = self.ascii_image[k][minStart-1:].rstrip().replace(" ","⠀")
            # self.ascii_image[k] = self.ascii_image[k][minStart-1:].rstrip().replace(" ","⚫")

            self.ascii_image[k] = self.ascii_image[k][minStart:-1*(minEnd)].replace(" ","⚫")
        self.ascii_image = "\n".join(self.ascii_image)
        if outputFile is not None:
            with open(outputFile, "w") as f:
                f.write(self.ascii_image)
        print(self.ascii_image)

    def resizeImage(self,image):
        width, height = image.size
        ratio = height/width
        new_height = int(self.width * ratio)
        resized_image = image.resize((self.width, new_height))

        return(resized_image)


    def converToGrayscale(self,image):
        grayscale_image = image.convert("L")
        return(grayscale_image)


    def matchPixel(self,pixel):
        rate = 255*255*255
        chosenColor = ASCII_CHARS[::-1][0]
        for k in range(len(ASCII_CHARSv)):
            color = ASCII_CHARSv[k]
            vRate = abs(color[0]-pixel[0])*abs(color[1]-pixel[1])*abs(color[2]-pixel[2])
            if vRate < rate:
                rate = vRate
                chosenColor = k

        return ASCII_CHARS[chosenColor]

    def pixelsToAscii(self,image):
        pixels = image.getdata()
        print("@@@@@@@@@@@@@@@@@@@")
        print("@@@@@@@@@@@@@@@@@@@")
        print(pixels)
        print("@@@@@@@@@@@@@@@@@@@")
        print("@@@@@@@@@@@@@@@@@@@")
        # characters = "".join([ASCII_CHARS[pixel//80] for pixel in pixels])
        # characters = "".join([ASCII_CHARS[sum(pixel)//80] for pixel in pixels])
        characters = "".join([self.matchPixel(pixel) for pixel in pixels])
        return(characters)
# #
# from AsciService import *
# ITA("test/thumnail.jpg",30)
# ITA("test/pp.jpeg",30)
# ITA("test/pp2.jpeg",30)
