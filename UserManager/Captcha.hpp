#pragma once
#include <random>

#include "opencv2/opencv.hpp"

class Captcha {
public:
    static auto mat_to_jpeg_string(const cv::Mat& mat, const int jpeg_quality = 95) -> std::string {
        if (mat.empty())
            throw std::invalid_argument("输入矩阵为空!");
        if (jpeg_quality < 0 || jpeg_quality > 100)
            throw std::invalid_argument("JPEG格式质量需要在0-100之间!");

        const int depth = mat.depth();
        if (depth != CV_8U)
            throw std::invalid_argument("只支持8bit无符号整数!");

        const int channels = mat.channels();
        if (channels != 1 && channels != 3)
            throw std::invalid_argument("输入矩阵的通道数必须是1（灰度）或3（BGR）!");

        std::vector<int> compression_params = {
            cv::IMWRITE_JPEG_QUALITY,
            jpeg_quality,
            cv::IMWRITE_JPEG_PROGRESSIVE,
            1
        };

        std::vector<uchar> buffer;
        buffer.resize(mat.total() * mat.elemSize());

        if (!imencode(".jpg", mat, buffer, compression_params))
            throw std::runtime_error("无法编码图片为JPEG!");

        if (buffer.empty())
            throw std::runtime_error("缓冲区为空!");

        std::string result(buffer.size() + 1, '\0');
        std::memcpy(result.data(), buffer.data(), buffer.size());

        return result;
    }

    static auto generate_captcha(const std::string& code, const int width = 300, const int height = 80, const int lines = 15, const int dots = 500) -> cv::Mat {
        cv::Mat img(height, width, CV_8UC3, cv::Scalar(255, 255, 255));
        cv::RNG rng(time(nullptr));

        parallel_for_(cv::Range(0, img.rows),
                      [&](const cv::Range& range) {
                          for (int y = range.start; y < range.end; ++y) {
                              cv::Vec3b* ptr = img.ptr<cv::Vec3b>(y);
                              for (int x = 0; x < img.cols; ++x)
                                  ptr[x] = cv::Vec3b(200 + rng.uniform(0, 55), 200 + rng.uniform(0, 55), 200 + rng.uniform(0, 55));
                          }
                      });

        parallel_for_(cv::Range(0, lines),
                      [&](const cv::Range& range) {
                          for (int i = range.start; i < range.end; ++i) {
                              line(img,
                                   cv::Point(rng.uniform(0, width), rng.uniform(0, height)),
                                   cv::Point(rng.uniform(0, width), rng.uniform(0, height)),
                                   cv::Scalar(rng.uniform(0, 255), rng.uniform(0, 255), rng.uniform(0, 255)),
                                   rng.uniform(1, 2));
                          }
                      });

        parallel_for_(cv::Range(0, dots),
                      [&](const cv::Range& range) {
                          for (int i = range.start; i < range.end; ++i)
                              img.at<cv::Vec3b>(rng.uniform(0, height), rng.uniform(0, width)) = cv::Vec3b(rng.uniform(0, 255), rng.uniform(0, 255), rng.uniform(0, 255));
                      });

        constexpr int fontFace = cv::FONT_HERSHEY_COMPLEX_SMALL;
        int xOffset = 20;

        for (const char i : code) {
            constexpr int charSpacing = 10;
            const double fontScale = rng.uniform(1.2, 1.8);
            const int thickness = rng.uniform(2, 4);
            const cv::Scalar color(rng.uniform(0, 150), rng.uniform(0, 150), rng.uniform(0, 150));
            int baseline = 0;
            const int angle = rng.uniform(-30, 30);

            const cv::Size textSize = cv::getTextSize(std::string(1, i), fontFace, fontScale, thickness, &baseline);

            cv::Mat charImg(textSize.height * 2, textSize.width * 2, CV_8UC3, cv::Scalar(0, 0, 0));
            const cv::Point textOrg(charImg.cols / 2 - textSize.width / 2, charImg.rows / 2 + textSize.height / 2);
            putText(charImg, std::string(1, i), textOrg, fontFace, fontScale, color, thickness, cv::LINE_AA);

            cv::Mat rotationMatrix = getRotationMatrix2D(cv::Point2f(charImg.cols / 2.0f, charImg.rows / 2.0f), angle, 1.0);

            cv::Mat rotatedChar;
            warpAffine(charImg, rotatedChar, rotationMatrix, charImg.size(), cv::INTER_LINEAR, cv::BORDER_CONSTANT, cv::Scalar(0, 0, 0));

            const int yPos = height / 2 + rng.uniform(-10, 10);
            cv::Rect roi(xOffset + rng.uniform(-5, 5), yPos - rotatedChar.rows / 2, rotatedChar.cols, rotatedChar.rows);

            parallel_for_(cv::Range(0, rotatedChar.rows),
                          [&](const cv::Range& range) {
                              for (int y = range.start; y < range.end; ++y) {
                                  for (int x = 0; x < rotatedChar.cols; ++x) {
                                      if (roi.x + x < width && roi.y + y < height && roi.x + x >= 0 && roi.y + y >= 0) {
                                          cv::Vec3b pixel = rotatedChar.at<cv::Vec3b>(y, x);
                                          if (pixel != cv::Vec3b(0, 0, 0))
                                              img.at<cv::Vec3b>(roi.y + y, roi.x + x) = pixel;
                                      }
                                  }
                              }
                          });

            xOffset += textSize.width + charSpacing + rng.uniform(-5, 5);
        }

        return img;
    }

    static auto generate_verification_code(const int length) -> std::string {
        if (length <= 0)
            throw std::invalid_argument("长度必须是整数!");

        const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789";

        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<size_t> distribution(0, characters.size() - 1);

        std::string code;
        code.reserve(length);

        for (int i = 0; i < length; ++i)
            code += characters[distribution(generator)];

        return code;
    }
};
