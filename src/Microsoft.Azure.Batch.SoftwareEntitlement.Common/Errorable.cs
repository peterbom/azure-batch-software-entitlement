using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Common
{
    /// <summary>
    /// Factory methods for instances of <see cref="Errorable{T}"/>
    /// </summary>
    public static class Errorable
    {
        /// <summary>
        /// Create a value that represents a successful operation with a result
        /// </summary>
        /// <typeparam name="T">The type of value contained.</typeparam>
        /// <param name="value">Result value to wrap.</param>
        /// <returns>An errorable containing the provided value.</returns>
        public static Errorable<T> Success<T>(T value)
            => Errorable<T>.CreateSuccess(value);

        /// <summary>
        /// Create a value that represents a failed operation
        /// </summary>
        /// <typeparam name="T">The type of value that might have been contained.</typeparam>
        /// <param name="errors">Sequence of error messages.</param>
        /// <returns>An errorable containing the specified errors.</returns>
        public static Errorable<T> Failure<T>(IEnumerable<string> errors)
            => Errorable<T>.CreateFailure(errors);

        /// <summary>
        /// Create a value that represents a failed operation
        /// </summary>
        /// <typeparam name="T">The type of value that might have been contained.</typeparam>
        /// <param name="error">Sequence of error messages.</param>
        /// <returns>An errorable containing the specified error.</returns>
        public static Errorable<T> Failure<T>(string error)
            => Errorable<T>.CreateFailure(error);
    }

    /// <summary>
    /// A container that either contains a value or a set of errors
    /// </summary>
    /// <typeparam name="T">The type of value contained in the successful case.</typeparam>
    public class Errorable<T>
    {
        /// <summary>
        /// A value indicating whether we have a value
        /// </summary>
        private readonly bool _hasValue;

        /// <summary>
        /// The value wrapped by this <see cref="Errorable{T}"/>
        /// </summary>
        /// <exception cref="InvalidOperationException">If no value is available.</exception>
        private readonly T _value;

        /// <summary>
        /// Gets the (possibly empty) set of errors reported
        /// </summary>
        private readonly ImmutableHashSet<string> _errors;

        private Errorable(
            T value,
            ImmutableHashSet<string> errors,
            bool hasValue)
        {
            _value = value;
            _errors = errors;
            _hasValue = hasValue;
        }

        public static Errorable<T> CreateSuccess(T value)
            => new Errorable<T>(value, ImmutableHashSet.Create<string>(), true);

        public static Errorable<T> CreateFailure(IEnumerable<string> errors)
            => CreateFailure(errors.ToArray());

        public static Errorable<T> CreateFailure(params string[] errors)
        {
            if (errors == null)
            {
                throw new ArgumentNullException(nameof(errors));
            }

            if (errors.Length == 0)
            {
                throw new ArgumentException("At least one error must be specified.");
            }

            return new Errorable<T>(default, ImmutableHashSet.Create(errors), false);
        }

        /// <summary>
        /// Call one function or another depending on whether we have a value or some errors
        /// </summary>
        /// <remarks>Both functions must return the same type.</remarks>
        /// <typeparam name="TNext">Type of value to return.</typeparam>
        /// <param name="whenSuccessful">Function to call when we have a value.</param>
        /// <param name="whenFailure">Function to call when we have errors.</param>
        /// <returns>The result of the function that was called.</returns>
        private TNext Match<TNext>(
            Func<T, TNext> whenSuccessful,
            Func<IEnumerable<string>, TNext> whenFailure)
            => _hasValue ? whenSuccessful(_value) : whenFailure(_errors);

        public Errorable<TNext> Then<TNext>(Func<T, TNext> operation)
        {
            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation));
            }

            return Match(
                whenSuccessful: t => (Errorable<TNext>)operation(t),
                whenFailure: t => Errorable<TNext>.CreateFailure(_errors));
        }

        /// <summary>
        /// Executes a function returning an <see cref="Errorable{T}"/> conditionally, depending
        /// on the result of this <see cref="Errorable{T}"/> instance.
        /// </summary>
        /// <typeparam name="TNew">The return type of <paramref name="operation"/></typeparam>
        /// <param name="operation">A function to execute on the value of this instance if it
        /// is successful</param>
        /// <returns>
        /// An <see cref="Errorable{T}"/> containing the result of executing <paramref name="operation"/>
        /// if the input was sucessful, or the errors from this instance otherwise.
        /// </returns>
        public Errorable<TNext> Then<TNext>(Func<T, Errorable<TNext>> operation)
        {
            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation));
            }

            return Match(
                whenSuccessful: t => operation(t),
                whenFailure: errors => Errorable<TNext>.CreateFailure(errors));
        }

        public static implicit operator Errorable<T>(T value)
            => CreateSuccess(value);

        public static implicit operator Errorable<T>(string error)
            => CreateFailure(error);
    }
}
