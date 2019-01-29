using System;
using FluentAssertions;
using Xunit;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Common.Tests
{
    public abstract class ResultExtensionTests
    {
        protected const int DefaultOkInt = 12;
        protected const int DefaultOtherOkInt = 42;

        protected const string DefaultErrorString = "error";
        protected const string DefaultOtherErrorString = "other";

        protected static readonly Result<int, CombinableString> OkIntResult = new Result<int, CombinableString>(DefaultOkInt);
        protected static readonly Result<int, CombinableString> OtherOkIntResult = new Result<int, CombinableString>(DefaultOtherOkInt);

        protected static readonly Result<int, CombinableString> ErrorIntResult = new Result<int, CombinableString>(DefaultErrorString);
        protected static readonly Result<int, CombinableString> OtherErrorIntResult =
            new Result<int, CombinableString>(DefaultOtherErrorString);

        protected static readonly Result<int, CombinableString> MissingIntResult = null;

        protected class CombinableString : ICombinable<CombinableString>
        {
            public CombinableString(string value)
            {
                Content = value;
            }

            public CombinableString Combine(CombinableString combinable)
                => new CombinableString($"{Content}, {combinable.Content}");

            public string Content { get; }

            public static implicit operator CombinableString(string value) =>
                new CombinableString(value);
        }

        public class WithReturningTuple : ResultExtensionTests
        {
            [Fact]
            public void GivenNullFirst_ThrowsExpectedException()
            {
                var exception =
                    Assert.Throws<ArgumentNullException>(
                        () => MissingIntResult.With(OkIntResult));
                exception.Should().NotBeNull();
                exception.ParamName.Should().Be("first");
            }

            [Fact]
            public void GivenNullSecond_ThrowsExpectedException()
            {
                var exception =
                    Assert.Throws<ArgumentNullException>(
                        () => OkIntResult.With(MissingIntResult));
                exception.Should().NotBeNull();
                exception.ParamName.Should().Be("second");
            }

            [Fact]
            public void GivenErrorFirst_ReturnsSameErrors()
            {
                var result = ErrorIntResult.With(OkIntResult);
                result.GetError().Content.Should().Be(DefaultErrorString);
            }

            [Fact]
            public void GivenErrorSecond_ReturnsSameErrors()
            {
                var result = OkIntResult.With(ErrorIntResult);
                result.GetError().Content.Should().Be(DefaultErrorString);
            }

            [Fact]
            public void GivenErrorOnBothSides_ReturnsAllErrors()
            {
                var result = ErrorIntResult.With(OtherErrorIntResult);
                result.GetError().Content.Should().Be($"{DefaultErrorString}, {DefaultOtherErrorString}");
            }

            [Fact]
            public void GivenSuccessOnBothSides_ReturnsExpectedTuple()
            {
                var result = OkIntResult.With(OtherOkIntResult);
                result.GetOk().Should().Be((DefaultOkInt, DefaultOtherOkInt));
            }
        }
        
        public class MergeSameType : ResultExtensionTests
        {
            [Fact]
            public void WhenOk_ReturnsOk()
            {
                var right = new Result<int, int>(ok: 7);
                var result = right.Merge();
                result.Should().Be(7);
            }

            [Fact]
            public void WhenError_ReturnsError()
            {
                var errorResult = new Result<int, int>(error: 47);
                var result = errorResult.Merge();
                result.Should().Be(47);
            }
        }

        public class MergeDifferentTypes : ResultExtensionTests
        {
            [Fact]
            public void WhenOk_ReturnsOk()
            {
                var result = OkIntResult.Merge(e => -1);
                result.Should().Be(DefaultOkInt);
            }

            [Fact]
            public void WhenError_ReturnsConvertedError()
            {
                var result = ErrorIntResult.Merge(i => -1);
                result.Should().Be(-1);
            }
        }

        public class OnErrorWithAction : ResultExtensionTests
        {
            [Fact]
            public void WhenError_CallsSuppliedAction()
            {
                bool invoked = false;
                ErrorIntResult.OnError(i =>
                {
                    invoked = true;
                });
                invoked.Should().Be(true);
            }

            [Fact]
            public void WhenOk_DoesNotCallSuppliedAction()
            {
                bool invoked = false;
                OkIntResult.OnError(i =>
                {
                    invoked = true;
                });
                invoked.Should().Be(false);
            }
        }

        public class OnErrorWithFunc : ResultExtensionTests
        {
            [Fact]
            public void WhenError_CallsSuppliedFunc()
            {
                bool invoked = false;
                var result = ErrorIntResult.OnError(error =>
                {
                    invoked = true;
                    return error.Content + "!";
                });

                invoked.Should().Be(true);
                result.GetError().Should().Be(DefaultErrorString + "!");
            }

            [Fact]
            public void WhenOk_DoesNotCallSuppliedFunc()
            {
                bool invoked = false;
                var result = OkIntResult.OnError(error =>
                {
                    invoked = true;
                    return error + "!";
                });

                invoked.Should().Be(false);
                result.IsOk().Should().BeTrue();
            }
        }

        public class OnOkWithAction : ResultExtensionTests
        {
            [Fact]
            public void WhenError_DoesNotCallSuppliedAction()
            {
                bool invoked = false;
                ErrorIntResult.OnOk(i =>
                {
                    invoked = true;
                });
                invoked.Should().Be(false);
            }

            [Fact]
            public void WhenOk_CallsSuppliedAction()
            {
                bool invoked = false;
                OkIntResult.OnOk(i =>
                {
                    invoked = true;
                });
                invoked.Should().Be(true);
            }
        }

        public class OnOkWithFunc : ResultExtensionTests
        {
            [Fact]
            public void WhenError_DoesNotCallSuppliedFunc()
            {
                bool invoked = false;
                var result = ErrorIntResult.OnOk(i =>
                {
                    invoked = true;
                    return i + 1;
                });

                invoked.Should().Be(false);
                result.IsError().Should().BeTrue();
            }

            [Fact]
            public void WhenOk_CallsSuppliedFunc()
            {
                bool invoked = false;
                var result = OkIntResult.OnOk(i =>
                {
                    invoked = true;
                    return i + 1;
                });

                invoked.Should().Be(true);
                result.IsOk().Should().BeTrue();
                result.GetOk().Should().Be(DefaultOkInt + 1);
            }
        }

        public class OnOkWithResultFunc : ResultExtensionTests
        {
            [Fact]
            public void WhenError_DoesNotCallSuppliedFunc()
            {
                bool invoked = false;
                var result = ErrorIntResult.OnOk(i =>
                {
                    invoked = true;
                    return new Result<int, CombinableString>(i + 1);
                });

                invoked.Should().Be(false);
                result.IsError().Should().BeTrue();
            }

            [Fact]
            public void WhenOk_CallsSuppliedFunc()
            {
                bool invoked = false;
                var result = OkIntResult.OnOk(i =>
                {
                    invoked = true;
                    return new Result<int, CombinableString>(i + 1);
                });

                invoked.Should().Be(true);
                result.IsOk().Should().BeTrue();
                result.GetOk().Should().Be(DefaultOkInt + 1);
            }
        }
    }
}
